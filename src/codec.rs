/// Serialize `self` into a byte buffer for transmission.
pub trait Encode: Send + 'static {
    /// # Errors
    /// Returns `Err` if serialization fails.
    fn encode_to_bytes(&self) -> Result<Vec<u8>, crate::Error>;
}

/// Deserialize `Self` from a received byte buffer.
pub trait Decode: Sized + Send + 'static {
    /// # Errors
    /// Returns `Err` if deserialization fails or the bytes are malformed.
    fn decode_from_bytes(bytes: &[u8]) -> Result<Self, crate::Error>;
}

// ── bitcode-only ──────────────────────────────────────────────────────────────
// encode is infallible; decode carries a concrete bitcode::Error.

#[cfg(all(feature = "bitcode", not(feature = "serde")))]
impl<T: bitcode::Encode + Send + 'static> Encode for T {
    fn encode_to_bytes(&self) -> Result<Vec<u8>, crate::Error> {
        Ok(bitcode::encode(self))
    }
}

#[cfg(all(feature = "bitcode", not(feature = "serde")))]
impl<T: for<'de> bitcode::Decode<'de> + Send + 'static> Decode for T {
    fn decode_from_bytes(bytes: &[u8]) -> Result<Self, crate::Error> {
        bitcode::decode(bytes).map_err(crate::Error::Decode)
    }
}

// ── serde-only ────────────────────────────────────────────────────────────────
// postcard is used; both directions carry a concrete postcard::Error.

#[cfg(all(feature = "serde", not(feature = "bitcode")))]
impl<T: serde::Serialize + Send + 'static> Encode for T {
    fn encode_to_bytes(&self) -> Result<Vec<u8>, crate::Error> {
        postcard::to_allocvec(self).map_err(crate::Error::Encode)
    }
}

#[cfg(all(feature = "serde", not(feature = "bitcode")))]
impl<T: serde::de::DeserializeOwned + Send + 'static> Decode for T {
    fn decode_from_bytes(bytes: &[u8]) -> Result<Self, crate::Error> {
        postcard::from_bytes(bytes).map_err(crate::Error::Decode)
    }
}

// ── both features active ──────────────────────────────────────────────────────
// serde/postcard wins; errors are boxed since the active codec is ambiguous.

#[cfg(all(feature = "serde", feature = "bitcode"))]
impl<T: serde::Serialize + Send + 'static> Encode for T {
    fn encode_to_bytes(&self) -> Result<Vec<u8>, crate::Error> {
        postcard::to_allocvec(self).map_err(|e| crate::Error::Encode(Box::new(e)))
    }
}

#[cfg(all(feature = "serde", feature = "bitcode"))]
impl<T: serde::de::DeserializeOwned + Send + 'static> Decode for T {
    fn decode_from_bytes(bytes: &[u8]) -> Result<Self, crate::Error> {
        postcard::from_bytes(bytes).map_err(|e| crate::Error::Decode(Box::new(e)))
    }
}
