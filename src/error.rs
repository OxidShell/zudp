use std::net::SocketAddr;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Failed to encode message: {0}")]
    Encode(String),
    #[error("Failed to decode message: {0}")]
    Decode(String),
    #[error("Receive channel closed — engine task has stopped")]
    ChannelClosed,
    #[error("Message requires {got} fragments but maximum is {max}")]
    MessageTooLarge { got: usize, max: usize },
    #[error("No route to relay peer: {0}")]
    UnknownRelay(SocketAddr),
    #[error("Invalid frame: {0}")]
    InvalidFrame(String),
}
