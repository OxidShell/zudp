use std::{collections::HashMap, time::Instant};

use bytes::{Bytes, BytesMut};

/// Maximum fragments per message on the **send** side (`frag_idx` is a `u16`).
pub const MAX_FRAGMENTS: usize = u16::MAX as usize;

/// Maximum `frag_total` accepted on the **receive** side.
///
/// Caps the `Vec` pre-allocation in `Assembly` — a peer sending `frag_total = u16::MAX`
/// would otherwise allocate 64 KB of slot entries per in-flight message ID.
/// 1 024 fragments × 1 400 B MTU ≈ 1.4 MB max message size, sufficient for gaming.
const MAX_FRAG_RECV: u16 = 1_024;

/// Maximum number of incomplete assemblies tracked simultaneously per `(peer, stream)`.
///
/// Bounds memory under a flood of distinct `msg_id` values without reassembly.
const MAX_CONCURRENT_ASSEMBLIES: usize = 64;

struct Assembly {
    total: u16,
    received: u16,
    /// Indexed by `frag_idx`; pre-allocated to `total` slots.
    pieces: Vec<Option<Bytes>>,
    started_at: Instant,
}

/// Reassembles fragmented messages from individual `Fragment` frames.
pub struct FragAssembler {
    in_flight: HashMap<u32, Assembly>,
}

impl FragAssembler {
    #[must_use]
    pub fn new() -> Self {
        Self {
            in_flight: HashMap::new(),
        }
    }

    /// Insert one fragment; returns the reassembled message when all pieces have arrived.
    ///
    /// Returns `None` without inserting if `frag_total` exceeds [`MAX_FRAG_RECV`] or if
    /// the concurrent assembly cap ([`MAX_CONCURRENT_ASSEMBLIES`]) would be exceeded.
    #[must_use]
    pub fn insert(
        &mut self,
        msg_id: u32,
        frag_idx: u16,
        frag_total: u16,
        payload: Bytes,
    ) -> Option<Bytes> {
        if frag_total == 0 || frag_total > MAX_FRAG_RECV {
            tracing::warn!(
                target: "zudp::frag",
                msg_id, frag_total, max = MAX_FRAG_RECV,
                "fragment total out of range — dropping"
            );
            return None;
        }
        if frag_idx >= frag_total {
            return None;
        }

        let is_new = !self.in_flight.contains_key(&msg_id);
        if is_new && self.in_flight.len() >= MAX_CONCURRENT_ASSEMBLIES {
            tracing::warn!(
                target: "zudp::frag",
                msg_id, cap = MAX_CONCURRENT_ASSEMBLIES,
                "concurrent assembly cap reached — dropping fragment"
            );
            return None;
        }

        let assembly = self.in_flight.entry(msg_id).or_insert_with(|| Assembly {
            total: frag_total,
            received: 0,
            // Pre-allocate exactly `frag_total` slots — O(1) index access, no hash overhead.
            pieces: vec![None; frag_total as usize],
            started_at: Instant::now(),
        });

        if assembly.pieces[frag_idx as usize]
            .replace(payload)
            .is_none()
        {
            assembly.received += 1;
        }

        if assembly.received < assembly.total {
            return None;
        }

        let assembly = self.in_flight.remove(&msg_id)?;
        // Pre-size the output buffer to avoid reallocs during concat.
        let total_bytes: usize = assembly.pieces.iter().flatten().map(Bytes::len).sum();
        let mut out = BytesMut::with_capacity(total_bytes);
        for piece in assembly.pieces.into_iter().flatten() {
            out.extend_from_slice(&piece);
        }
        Some(out.freeze())
    }

    /// Discard incomplete assemblies that have been in-flight longer than `max_age`.
    pub fn prune(&mut self, max_age: std::time::Duration) {
        let cutoff = Instant::now()
            .checked_sub(max_age)
            .unwrap_or(Instant::now());
        self.in_flight.retain(|_, a| a.started_at > cutoff);
    }
}

/// Split `data` into chunks of at most `mtu` bytes.
///
/// Each chunk is a zero-copy [`Bytes`] slice of the original buffer.
/// Returns `Err` if more than `u16::MAX` fragments would be required.
pub fn fragment(data: &Bytes, mtu: usize) -> Result<Vec<Bytes>, crate::Error> {
    let total = data.len().div_ceil(mtu);
    if total > MAX_FRAGMENTS {
        return Err(crate::Error::MessageTooLarge {
            got: total,
            max: MAX_FRAGMENTS,
        });
    }
    let chunks = (0..total)
        .map(|i| data.slice(i * mtu..((i + 1) * mtu).min(data.len())))
        .collect();
    Ok(chunks)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::Bytes;

    use super::*;

    #[test]
    fn single_fragment_completes_immediately() {
        let mut fa = FragAssembler::new();
        let data = Bytes::from_static(b"hello");
        let result = fa.insert(0, 0, 1, data.clone());
        assert_eq!(result.unwrap(), data);
        assert!(fa.in_flight.is_empty(), "completed assembly must be removed");
    }

    #[test]
    fn out_of_order_fragments_reassemble_correctly() {
        let mut fa = FragAssembler::new();
        let a = Bytes::from_static(b"hello");
        let b = Bytes::from_static(b" world");
        // frag 1 arrives before frag 0.
        assert!(fa.insert(1, 1, 2, b).is_none());
        let result = fa.insert(1, 0, 2, a);
        assert_eq!(result.unwrap(), Bytes::from_static(b"hello world"));
    }

    #[test]
    fn fragment_bomb_above_max_rejected() {
        let mut fa = FragAssembler::new();
        let result = fa.insert(99, 0, MAX_FRAG_RECV + 1, Bytes::from_static(b"evil"));
        assert!(result.is_none(), "frag_total > MAX_FRAG_RECV must be rejected");
        assert!(fa.in_flight.is_empty(), "no slot should be allocated for rejected frames");
    }

    #[test]
    fn fragment_zero_total_rejected() {
        let mut fa = FragAssembler::new();
        let result = fa.insert(0, 0, 0, Bytes::from_static(b"bad"));
        assert!(result.is_none());
        assert!(fa.in_flight.is_empty());
    }

    #[test]
    fn frag_idx_out_of_bounds_rejected() {
        let mut fa = FragAssembler::new();
        // frag_idx == frag_total is invalid (must be < frag_total).
        let result = fa.insert(0, 3, 3, Bytes::from_static(b"bad"));
        assert!(result.is_none());
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn concurrent_assembly_cap_enforced() {
        let mut fa = FragAssembler::new();
        // Fill exactly MAX_CONCURRENT_ASSEMBLIES incomplete assemblies.
        for id in 0..(MAX_CONCURRENT_ASSEMBLIES as u32) {
            let result = fa.insert(id, 0, 2, Bytes::from_static(b"x"));
            assert!(result.is_none(), "incomplete assembly should not complete on frag 0");
        }
        assert_eq!(fa.in_flight.len(), MAX_CONCURRENT_ASSEMBLIES);

        // One more distinct msg_id must be rejected.
        #[allow(clippy::cast_possible_truncation)]
        let overflow_id = MAX_CONCURRENT_ASSEMBLIES as u32;
        let result = fa.insert(overflow_id, 0, 2, Bytes::from_static(b"overflow"));
        assert!(result.is_none(), "assembly beyond cap must be rejected");
        assert_eq!(
            fa.in_flight.len(),
            MAX_CONCURRENT_ASSEMBLIES,
            "cap must not be exceeded"
        );
    }

    #[test]
    fn duplicate_fragment_does_not_double_count() {
        let mut fa = FragAssembler::new();
        let piece = Bytes::from_static(b"chunk");
        let _ = fa.insert(1, 0, 2, piece.clone());
        let _ = fa.insert(1, 0, 2, piece.clone()); // duplicate of frag 0
        // Assembly should still be waiting for frag 1 — received must be 1, not 2.
        let asm = fa.in_flight.get(&1).expect("assembly should be in flight");
        assert_eq!(asm.received, 1, "duplicate must not increment received count");
    }

    #[test]
    fn prune_keeps_fresh_assemblies() {
        let mut fa = FragAssembler::new();
        let _ = fa.insert(0, 0, 2, Bytes::from_static(b"piece0"));
        fa.prune(Duration::from_hours(1)); // huge max_age — nothing should be pruned
        assert_eq!(fa.in_flight.len(), 1, "fresh assembly must survive prune");
    }

    #[test]
    fn prune_removes_stale_assemblies() {
        let mut fa = FragAssembler::new();
        let _ = fa.insert(0, 0, 2, Bytes::from_static(b"piece0"));
        // Sleep past the max_age threshold so the assembly is considered stale.
        std::thread::sleep(Duration::from_millis(5));
        fa.prune(Duration::from_millis(1));
        assert_eq!(fa.in_flight.len(), 0, "stale assembly must be removed by prune");
    }
}
