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
/// Exported for callers that want an explicit window of their own; ZUDP's secure
/// channels already reject replayed frames with a wider internal window.
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

/// Nonces tracked by [`NonceWindow`].  Sized for reordering, not for loss: at 10 000
/// frames per second a frame may still arrive 400 ms behind the newest one.
const NONCE_WINDOW: u64 = 4_096;
const NONCE_WORDS: usize = (NONCE_WINDOW / 64) as usize;

/// Anti-replay window over the last [`NONCE_WINDOW`] authenticated nonces.
///
/// Every Secure frame is accepted at most once, whichever path it arrived on — a relay
/// that re-sends an old frame, or an attacker that replays a captured datagram, gets
/// nothing delivered.  Frames older than the window are rejected too.
struct NonceWindow {
    /// Highest nonce accepted so far; `None` before the first one.
    highest: Option<u64>,
    /// Bit `n % NONCE_WINDOW` is set once nonce `n` (within the window) was accepted.
    seen: [u64; NONCE_WORDS],
}

impl Default for NonceWindow {
    fn default() -> Self {
        Self {
            highest: None,
            seen: [0; NONCE_WORDS],
        }
    }
}

impl NonceWindow {
    fn bit(nonce: u64) -> (usize, u64) {
        let slot = nonce % NONCE_WINDOW;
        // slot / 64 < NONCE_WORDS, so the cast cannot truncate.
        #[allow(clippy::cast_possible_truncation)]
        let word = (slot / 64) as usize;
        (word, 1 << (slot % 64))
    }

    /// Record `nonce`; `false` when it was already accepted or is too old.
    fn accept(&mut self, nonce: u64) -> bool {
        let highest = match self.highest {
            Some(highest) if nonce <= highest => {
                if highest - nonce >= NONCE_WINDOW {
                    return false;
                }
                let (word, mask) = Self::bit(nonce);
                let fresh = self.seen[word] & mask == 0;
                self.seen[word] |= mask;
                return fresh;
            }
            Some(highest) => highest,
            None => {
                self.highest = Some(nonce);
                let (word, mask) = Self::bit(nonce);
                self.seen[word] |= mask;
                return true;
            }
        };
        // Slide forward: the slots between the old and the new highest are now unseen.
        if nonce - highest >= NONCE_WINDOW {
            self.seen = [0; NONCE_WORDS];
        } else {
            for skipped in highest + 1..nonce {
                let (word, mask) = Self::bit(skipped);
                self.seen[word] &= !mask;
            }
        }
        let (word, mask) = Self::bit(nonce);
        self.seen[word] |= mask;
        self.highest = Some(nonce);
        true
    }
}

/// Established Noise transport state for one peer.
///
/// Wraps `StatelessTransportState` so each send/recv carries an explicit nonce,
/// which is necessary for UDP where packets may arrive out of order.  Received nonces
/// go through a [`NonceWindow`], so a replayed frame is rejected even when it carries
/// something the stream layer would not deduplicate (an unreliable datagram, a Ping).
pub struct SecureChannel {
    transport: Mutex<snow::StatelessTransportState>,
    send_nonce: AtomicU64,
    replay: Mutex<NonceWindow>,
    /// Session index we chose; the remote stamps it on Secure frames it sends us.
    local_index: u64,
    /// Session index the remote chose; stamped on every Secure frame we send it.
    remote_index: u64,
}

impl SecureChannel {
    pub fn new(
        transport: snow::StatelessTransportState,
        local_index: u64,
        remote_index: u64,
    ) -> Self {
        Self {
            transport: Mutex::new(transport),
            send_nonce: AtomicU64::new(0),
            replay: Mutex::new(NonceWindow::default()),
            local_index,
            remote_index,
        }
    }

    #[must_use]
    pub fn local_index(&self) -> u64 {
        self.local_index
    }

    #[must_use]
    pub fn remote_index(&self) -> u64 {
        self.remote_index
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
    /// Fails when the AEAD tag is wrong (wrong key, tampered payload, mismatched nonce) and
    /// when the nonce was already accepted or fell out of the replay window.  Only an
    /// authenticated frame advances the window, so forged frames cannot burn nonces.
    pub fn decrypt(&self, nonce: u64, ciphertext: &[u8]) -> Result<Vec<u8>, snow::Error> {
        let mut buf = vec![0u8; ciphertext.len()];
        let written = self
            .transport
            .lock()
            .read_message(nonce, ciphertext, &mut buf)?;
        if !self.replay.lock().accept(nonce) {
            return Err(snow::Error::Decrypt);
        }
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
    fn nonce_window_rejects_replays_and_stale_nonces() {
        let mut w = NonceWindow::default();
        assert!(w.accept(0));
        assert!(!w.accept(0));
        assert!(w.accept(5));
        assert!(w.accept(3), "reordered but fresh");
        assert!(!w.accept(3));
        assert!(w.accept(NONCE_WINDOW + 10));
        assert!(!w.accept(5), "slid out of the window");
        assert!(w.accept(NONCE_WINDOW + 9));
        assert!(w.accept(3 * NONCE_WINDOW), "a jump clears the window");
        assert!(!w.accept(3 * NONCE_WINDOW));
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

        let ch_i = SecureChannel::new(transport_i, 1, 2);
        let ch_r = SecureChannel::new(transport_r, 2, 1);

        let plaintext = b"hello zudp security";
        let (nonce, ciphertext) = ch_i.encrypt(plaintext).unwrap();
        let decrypted = ch_r.decrypt(nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
        assert!(
            ch_r.decrypt(nonce, &ciphertext).is_err(),
            "replayed frame accepted"
        );
    }

    #[test]
    fn wrong_key_rejected() {
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

        // Encrypting with one channel, decrypting with a different key → AEAD fail.
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let kp_c = Keypair::generate();

        let (ti, _) = handshake(&kp_a, &kp_b);
        let (_, tr_wrong) = handshake(&kp_a, &kp_c); // different session key

        let ch_send = SecureChannel::new(ti, 1, 2);
        let ch_recv_wrong = SecureChannel::new(tr_wrong, 2, 1);

        let (nonce, ciphertext) = ch_send.encrypt(b"secret").unwrap();
        // Wrong session key → AEAD tag mismatch → error.
        assert!(ch_recv_wrong.decrypt(nonce, &ciphertext).is_err());
    }
}
