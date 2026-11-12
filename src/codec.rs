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

#[cfg(all(
    feature = "bitcode",
    not(feature = "serde"),
    not(feature = "rkyv"),
    not(feature = "wincode")
))]
impl<T: bitcode::Encode + Send + 'static> Encode for T {
    fn encode_to_bytes(&self) -> Result<Vec<u8>, crate::Error> {
        Ok(bitcode::encode(self))
    }
}

#[cfg(all(
    feature = "bitcode",
    not(feature = "serde"),
    not(feature = "rkyv"),
    not(feature = "wincode")
))]
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
        > + Send
        + 'static,
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
    T::Archived: for<'a> rkyv::bytecheck::CheckBytes<rkyv::api::high::HighValidator<'a, rkyv::rancor::Error>>
        + rkyv::Deserialize<T, rkyv::api::high::HighDeserializer<rkyv::rancor::Error>>,
{
    fn decode_from_bytes(bytes: &[u8]) -> Result<Self, crate::Error> {
        rkyv::from_bytes::<T, rkyv::rancor::Error>(bytes)
            .map_err(|e| crate::Error::Decode(Box::new(e)))
    }
}

// wincode wins over bitcode and yields to rkyv and serde; both directions
// carry a boxed wincode error.

/// Layout of [`Encode`]/[`Decode`] with the `wincode` feature: bincode 2's
/// `standard()` (varint integers, little endian, varint lengths), with no
/// claimed length allowed to preallocate past 4 MiB.
#[cfg(all(feature = "wincode", not(feature = "serde"), not(feature = "rkyv")))]
pub type WincodeConfig = wincode::config::Configuration<
    true,
    { wincode::config::DEFAULT_PREALLOCATION_SIZE_LIMIT },
    wincode::len::BincodeLen,
    wincode::int_encoding::LittleEndian,
    wincode::int_encoding::VarInt,
    u32,
>;

#[cfg(all(feature = "wincode", not(feature = "serde"), not(feature = "rkyv")))]
impl<T> Encode for T
where
    T: wincode::SchemaWrite<WincodeConfig, Src = T> + Send + 'static,
{
    fn encode_to_bytes(&self) -> Result<Vec<u8>, crate::Error> {
        wincode::config::serialize(self, WincodeConfig::new())
            .map_err(|e| crate::Error::Encode(Box::new(e)))
    }
}

#[cfg(all(feature = "wincode", not(feature = "serde"), not(feature = "rkyv")))]
impl<T> Decode for T
where
    T: wincode::SchemaReadOwned<WincodeConfig, Dst = T> + Send + 'static,
{
    fn decode_from_bytes(bytes: &[u8]) -> Result<Self, crate::Error> {
        wincode::config::deserialize_exact(bytes, WincodeConfig::new())
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

#[cfg(all(
    test,
    feature = "wincode",
    not(feature = "serde"),
    not(feature = "rkyv")
))]
mod wincode_tests {
    use super::{Decode, Encode};

    #[test]
    fn messages_use_the_bincode_standard_layout() {
        assert_eq!(250_u32.encode_to_bytes().unwrap(), [250]);
        assert_eq!(251_u32.encode_to_bytes().unwrap(), [251, 251, 0]);
        let bytes = vec![1_u8, 2, 3].encode_to_bytes().unwrap();
        assert_eq!(bytes, [3, 1, 2, 3]);
        assert_eq!(Vec::<u8>::decode_from_bytes(&bytes).unwrap(), [1, 2, 3]);
    }

    #[test]
    fn a_forged_length_or_trailing_bytes_are_refused() {
        // Nine bytes claiming a vector of 2^56 elements.
        let mut forged = vec![0xfd];
        forged.extend_from_slice(&(1_u64 << 56).to_le_bytes());
        assert!(Vec::<u64>::decode_from_bytes(&forged).is_err());
        let mut long = 7_u32.encode_to_bytes().unwrap();
        long.push(0);
        assert!(u32::decode_from_bytes(&long).is_err());
    }
}
