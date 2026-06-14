//! Error type for the SEGB reader.

use thiserror::Error;

/// All errors that the SEGB reader can produce.
#[derive(Debug, Error)]
pub enum SegbError {
    /// The file / stream produced an I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The magic bytes at the expected position do not match `SEGB`.
    #[error("invalid SEGB magic: expected 53455342 (\"SEGB\"), got {found}")]
    BadMagic { found: String },

    /// The file header is shorter than expected.
    #[error("truncated header: need {need} bytes, got {got}")]
    TruncatedHeader { need: usize, got: usize },

    /// A record header is shorter than expected.
    #[error("truncated record header at offset {offset}: need {need} bytes, got {got}")]
    TruncatedRecordHeader { offset: u64, need: usize, got: usize },

    /// A record payload is shorter than the length field claims.
    #[error("truncated record payload at offset {offset}: need {need} bytes, got {got}")]
    TruncatedPayload { offset: u64, need: usize, got: usize },

    /// A `record_length` value is negative, which is not valid.
    #[error("invalid record length {length} at offset {offset}")]
    InvalidLength { offset: u64, length: i32 },

    /// `entries_count` in a SEGB v2 header is negative.
    #[error("invalid SEGB v2 entry count {count}")]
    InvalidEntryCount { count: i32 },

    /// The trailer size overflows the file size in SEGB v2.
    #[error("SEGB v2 trailer ({trailer_bytes} bytes) exceeds stream length ({stream_bytes} bytes)")]
    TrailerOverflow {
        trailer_bytes: u64,
        stream_bytes: u64,
    },

    /// An `EntryState` byte did not map to a known variant.
    #[error("unknown entry state value {0}")]
    UnknownState(i32),

    /// A seek operation was asked to go to a negative or overflow position.
    #[error("invalid seek offset: {0}")]
    InvalidSeek(String),

    /// A protobuf varint was longer than 10 bytes (malformed).
    #[error("malformed protobuf varint at byte offset {offset}")]
    MalformedVarint { offset: usize },

    /// A protobuf length-delimited field extends past the buffer end.
    #[error("protobuf length-delimited field at offset {offset} claims {length} bytes but only {remaining} remain")]
    ProtobufOverflow {
        offset: usize,
        length: usize,
        remaining: usize,
    },
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, SegbError>;
