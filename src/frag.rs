use std::{collections::HashMap, time::Instant};

use bytes::{Bytes, BytesMut};

/// Maximum fragments per message (`frag_idx` is a `u16`).
pub const MAX_FRAGMENTS: usize = u16::MAX as usize;

struct Assembly {
    total: u16,
    pieces: HashMap<u16, Bytes>,
    started_at: Instant,
}

/// Reassembles fragmented messages from individual `Fragment` frames.
///
/// Fully reassembled messages are returned from [`FragAssembler::insert`].
/// Incomplete assemblies older than a threshold can be discarded with [`FragAssembler::prune`].
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
            pieces: HashMap::new(),
            started_at: Instant::now(),
        });
        assembly.pieces.insert(frag_idx, payload);

        if assembly.pieces.len() != assembly.total as usize {
            return None;
        }

        let assembly = self.in_flight.remove(&msg_id)?;
        let mut out = BytesMut::new();
        for i in 0..assembly.total {
            // All pieces are present — unwrap is intentional (we checked len above).
            out.extend_from_slice(assembly.pieces.get(&i)?);
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
/// Each chunk is assigned a monotonically increasing fragment index starting at 0.
/// Returns `Err` if more than `u16::MAX` fragments would be required.
pub fn fragment(data: &[u8], mtu: usize) -> Result<Vec<Bytes>, crate::Error> {
    let total = data.len().div_ceil(mtu);
    if total > MAX_FRAGMENTS {
        return Err(crate::Error::MessageTooLarge {
            got: total,
            max: MAX_FRAGMENTS,
        });
    }
    let chunks: Vec<Bytes> = data.chunks(mtu).map(Bytes::copy_from_slice).collect();
    Ok(chunks)
}
