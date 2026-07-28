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

// encode is infallible for bitcode; decode carries a concrete bitcode::Error.

#[cfg(all(feature = "bitcode", not(feature = "serde"), not(feature = "rkyv")))]
impl<T: bitcode::Encode + Send + 'static> Encode for T {
    fn encode_to_bytes(&self) -> Result<Vec<u8>, crate::Error> {
        Ok(bitcode::encode(self))
    }
}

#[cfg(all(feature = "bitcode", not(feature = "serde"), not(feature = "rkyv")))]
impl<T: for<'de> bitcode::Decode<'de> + Send + 'static> Decode for T {
    fn decode_from_bytes(bytes: &[u8]) -> Result<Self, crate::Error> {
        bitcode::decode(bytes).map_err(crate::Error::Decode)
    }
}

// rkyv wins over bitcode; both directions carry a boxed rancor error.

#[cfg(all(feature = "rkyv", not(feature = "serde")))]
impl<T> Encode for T
where
    T: for<'a> rkyv::Serialize<
            rkyv::api::high::HighSerializer<
                rkyv::util::AlignedVec,
                rkyv::ser::allocator::ArenaHandle<'a>,
                rkyv::rancor::Error,
            >,
        > + Send + 'static,
{
    fn encode_to_bytes(&self) -> Result<Vec<u8>, crate::Error> {
        rkyv::to_bytes::<rkyv::rancor::Error>(self)
            .map(|v| v.to_vec())
            .map_err(|e| crate::Error::Encode(Box::new(e)))
    }
}

#[cfg(all(feature = "rkyv", not(feature = "serde")))]
impl<T> Decode for T
where
    T: rkyv::Archive + Send + 'static,
    T::Archived: for<'a> rkyv::bytecheck::CheckBytes<
            rkyv::api::high::HighValidator<'a, rkyv::rancor::Error>,
        > + rkyv::Deserialize<T, rkyv::api::high::HighDeserializer<rkyv::rancor::Error>>,
{
    fn decode_from_bytes(bytes: &[u8]) -> Result<Self, crate::Error> {
        rkyv::from_bytes::<T, rkyv::rancor::Error>(bytes)
            .map_err(|e| crate::Error::Decode(Box::new(e)))
    }
}

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
