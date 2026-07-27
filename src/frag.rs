use std::{collections::HashMap, time::Instant};

use bytes::{Bytes, BytesMut};

/// Maximum fragments per message (`frag_idx` is a `u16`).
pub const MAX_FRAGMENTS: usize = u16::MAX as usize;

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
    #[must_use]
    pub fn insert(
        &mut self,
        msg_id: u32,
        frag_idx: u16,
        frag_total: u16,
        payload: Bytes,
    ) -> Option<Bytes> {
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
