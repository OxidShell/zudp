use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;

const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// A Noise X25519 keypair used to authenticate and encrypt ZUDP connections.
#[derive(Clone)]
pub struct Keypair {
    pub public: [u8; 32],
    pub private: [u8; 32],
}

impl Keypair {
    /// Generate a fresh X25519 keypair using the OS RNG.
    ///
    /// # Panics
    /// Never panics in practice; panics only if the OS RNG is unavailable.
    #[must_use]
    pub fn generate() -> Self {
        let builder = snow::Builder::new(NOISE_PATTERN.parse().expect("valid noise pattern"));
        let kp = builder.generate_keypair().expect("X25519 keygen");
        let mut public = [0u8; 32];
        let mut private = [0u8; 32];
        public.copy_from_slice(&kp.public);
        private.copy_from_slice(&kp.private);
        Self { public, private }
    }

    /// Raw public key bytes (32 bytes, X25519).
    #[must_use]
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public
    }
}

pub fn build_initiator(kp: &Keypair) -> Result<snow::HandshakeState, snow::Error> {
    snow::Builder::new(NOISE_PATTERN.parse().expect("valid noise pattern"))
        .local_private_key(&kp.private)
        .build_initiator()
}

pub fn build_responder(kp: &Keypair) -> Result<snow::HandshakeState, snow::Error> {
    snow::Builder::new(NOISE_PATTERN.parse().expect("valid noise pattern"))
        .local_private_key(&kp.private)
        .build_responder()
}

/// 64-bit sliding window for AEAD anti-replay protection.
///
/// Tracks which nonces have been seen in the last 64 slots relative to `highest`.
/// Nonces more than 64 behind `highest` are unconditionally rejected.
///
/// Not used inside `SecureChannel` — ZUDP's own per-stream sequence tracking
/// handles deduplication. Exported for callers that want an explicit window.
#[derive(Default)]
pub struct ReplayWindow {
    highest: u64,
    /// Bitmask: bit `(highest - n)` is set if nonce `n` has been seen.
    window: u64,
}

impl ReplayWindow {
    /// Returns `true` and records the nonce if it is fresh; `false` if it is a replay or too old.
    pub fn check_and_update(&mut self, nonce: u64) -> bool {
        if nonce > self.highest {
            let shift = nonce - self.highest;
            self.window = if shift >= 64 { 0 } else { self.window << shift };
            self.window |= 1;
            self.highest = nonce;
            true
        } else {
            let diff = self.highest - nonce;
            if diff >= 64 {
                return false;
            }
            let bit = 1u64 << diff;
            if self.window & bit != 0 {
                false
            } else {
                self.window |= bit;
                true
            }
        }
    }
}

/// Established Noise transport state for one peer.
///
/// Wraps `StatelessTransportState` so each send/recv carries an explicit nonce,
/// which is necessary for UDP where packets may arrive out of order.
///
/// Replay deduplication is intentionally left to ZUDP's per-stream sequence
/// layer (`RecvState`). A crypto-layer replay window sized for normal traffic
/// rejects legitimate out-of-order fragments at high frame rates (e.g. >64
/// packets behind at 446 frags/sec ≈ 143 ms of jitter → false reject).
pub struct SecureChannel {
    transport: Mutex<snow::StatelessTransportState>,
    send_nonce: AtomicU64,
}

impl SecureChannel {
    pub fn new(transport: snow::StatelessTransportState) -> Self {
        Self {
            transport: Mutex::new(transport),
            send_nonce: AtomicU64::new(0),
        }
    }

    /// Encrypt `plaintext` using a fresh nonce. Returns `(nonce, ciphertext)`.
    ///
    /// The nonce must be included in the wire frame so the receiver can decrypt.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<(u64, Vec<u8>), snow::Error> {
        let nonce = self.send_nonce.fetch_add(1, Ordering::Relaxed);
        let mut buf = vec![0u8; plaintext.len() + 16]; // +16 for AEAD tag
        let written = self
            .transport
            .lock()
            .write_message(nonce, plaintext, &mut buf)?;
        buf.truncate(written);
        Ok((nonce, buf))
    }

    /// Decrypt `ciphertext` authenticated with `nonce`.
    ///
    /// Returns an error only if the AEAD authentication tag is wrong (wrong key,
    /// tampered payload, or mismatched nonce). True replay deduplication is
    /// handled by ZUDP's sequence layer, not here.
    pub fn decrypt(&self, nonce: u64, ciphertext: &[u8]) -> Result<Vec<u8>, snow::Error> {
        let mut buf = vec![0u8; ciphertext.len()];
        let written = self
            .transport
            .lock()
            .read_message(nonce, ciphertext, &mut buf)?;
        buf.truncate(written);
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_window_in_order() {
        let mut w = ReplayWindow::default();
        assert!(w.check_and_update(1));
        assert!(w.check_and_update(2));
        assert!(w.check_and_update(3));
        assert!(!w.check_and_update(2)); // replay
    }

    #[test]
    fn replay_window_out_of_order() {
        let mut w = ReplayWindow::default();
        assert!(w.check_and_update(5));
        assert!(w.check_and_update(3)); // out of order but within window
        assert!(!w.check_and_update(3)); // replay
    }

    #[test]
    fn replay_window_too_old() {
        let mut w = ReplayWindow::default();
        assert!(w.check_and_update(100));
        assert!(!w.check_and_update(35)); // 100 - 35 = 65 > 64, too old
    }

    #[test]
    fn replay_window_window_advance() {
        let mut w = ReplayWindow::default();
        assert!(w.check_and_update(1));
        assert!(w.check_and_update(65)); // big jump — window resets
        assert!(!w.check_and_update(1)); // now too old
    }

    #[test]
    fn noise_handshake_and_roundtrip() {
        let kp_i = Keypair::generate();
        let kp_r = Keypair::generate();

        let mut init = build_initiator(&kp_i).unwrap();
        let mut resp = build_responder(&kp_r).unwrap();

        let mut buf = vec![0u8; 256];

        // msg1: initiator → responder
        let n = init.write_message(&[], &mut buf).unwrap();
        let msg1 = buf[..n].to_vec();

        // msg2: responder reads msg1, writes msg2
        let mut tmp = vec![0u8; 256];
        resp.read_message(&msg1, &mut tmp).unwrap();
        let n = resp.write_message(&[], &mut buf).unwrap();
        let msg2 = buf[..n].to_vec();

        // msg3: initiator reads msg2, writes msg3
        let mut tmp2 = vec![0u8; 256];
        init.read_message(&msg2, &mut tmp2).unwrap();
        let n = init.write_message(&[], &mut buf).unwrap();
        let msg3 = buf[..n].to_vec();

        // finalize
        let mut tmp3 = vec![0u8; 256];
        resp.read_message(&msg3, &mut tmp3).unwrap();

        let transport_i = init.into_stateless_transport_mode().unwrap();
        let transport_r = resp.into_stateless_transport_mode().unwrap();

        let ch_i = SecureChannel::new(transport_i);
        let ch_r = SecureChannel::new(transport_r);

        let plaintext = b"hello zudp security";
        let (nonce, ciphertext) = ch_i.encrypt(plaintext).unwrap();
        let decrypted = ch_r.decrypt(nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_rejected() {
        // Encrypting with one channel, decrypting with a different key → AEAD fail.
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let kp_c = Keypair::generate();

        fn handshake(
            kp_i: &Keypair,
            kp_r: &Keypair,
        ) -> (snow::StatelessTransportState, snow::StatelessTransportState) {
            let mut init = build_initiator(kp_i).unwrap();
            let mut resp = build_responder(kp_r).unwrap();
            let mut buf = vec![0u8; 256];
            let mut tmp = vec![0u8; 256];
            let n = init.write_message(&[], &mut buf).unwrap();
            resp.read_message(&buf[..n], &mut tmp).unwrap();
            let n = resp.write_message(&[], &mut buf).unwrap();
            init.read_message(&buf[..n], &mut tmp).unwrap();
            let n = init.write_message(&[], &mut buf).unwrap();
            resp.read_message(&buf[..n], &mut tmp).unwrap();
            (
                init.into_stateless_transport_mode().unwrap(),
                resp.into_stateless_transport_mode().unwrap(),
            )
        }

        let (ti, _) = handshake(&kp_a, &kp_b);
        let (_, tr_wrong) = handshake(&kp_a, &kp_c); // different session key

        let ch_send = SecureChannel::new(ti);
        let ch_recv_wrong = SecureChannel::new(tr_wrong);

        let (nonce, ciphertext) = ch_send.encrypt(b"secret").unwrap();
        // Wrong session key → AEAD tag mismatch → error.
        assert!(ch_recv_wrong.decrypt(nonce, &ciphertext).is_err());
    }
}
