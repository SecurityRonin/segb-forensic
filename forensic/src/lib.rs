//! `segb-forensic` — anomaly auditor for Apple **SEGB** (Biome) streams.
//!
//! Consumes the version-neutral records produced by [`segb`] (the `segb-core`
//! reader) and emits graded anomaly findings via the shared
//! [`forensicnomicon::report`] model. The reader stays pure (no judgments); this
//! crate is where SEGB *forensic meaning* lives.
//!
//! SEGB streams are append-ordered logs of state-tagged, CRC-protected records.
//! That structure makes a small set of tampering / corruption signals precise:
//!
//! | Code | Severity | Meaning |
//! |---|---|---|
//! | `SEGB-CRC-MISMATCH` | High | record payload's CRC-32 ≠ stored CRC (corruption or post-write edit) |
//! | `SEGB-RECORD-DELETED` | Medium | a logically-`Deleted` record still present (recoverable deletion residue) |
//! | `SEGB-TIMESTAMP-OUT-OF-ORDER` | Medium | a `Written` record older than a preceding one (append-order broken ⇒ clock change / tamper) |
//! | `SEGB-TIMESTAMP-MISSING` | Low | a `Written` record with no finite timestamp |
//!
//! Findings are observations, never verdicts — the analyst concludes.

use forensicnomicon::report::{Evidence, Location, Observation, Severity};
use segb::{EntryState, SegbRecord};

/// A specific anomaly located at a record in the stream. Each variant carries
/// the record index and its payload byte offset for evidence.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum AnomalyKind {
    /// The CRC-32 computed over the payload does not match the stored CRC-32 —
    /// the payload was corrupted in transit/storage or edited after the record
    /// was written.
    CrcMismatch {
        /// Zero-based record index within the stream.
        index: usize,
        /// Byte offset of the payload.
        offset: u64,
        /// CRC-32 stored in the record header.
        stored: u32,
        /// CRC-32 recomputed over the payload bytes.
        computed: u32,
    },
    /// A record whose state is `Deleted` is still present in the stream and its
    /// payload is recoverable — deletion residue (potential anti-forensics).
    DeletedRecord {
        /// Zero-based record index within the stream.
        index: usize,
        /// Byte offset of the payload.
        offset: u64,
    },
    /// A `Written` record's timestamp predates a preceding `Written` record.
    /// SEGB streams are append-ordered, so a backwards step is consistent with
    /// clock manipulation or record reordering/tampering.
    TimestampOutOfOrder {
        /// Zero-based record index within the stream.
        index: usize,
        /// Byte offset of the payload.
        offset: u64,
        /// Timestamp (Unix seconds) of the preceding `Written` record.
        prev_unix: f64,
        /// Timestamp (Unix seconds) of this record.
        this_unix: f64,
    },
    /// A `Written` record carries no finite timestamp (the stored `f64` was NaN
    /// or infinite) — a malformed or zeroed time field.
    MissingTimestamp {
        /// Zero-based record index within the stream.
        index: usize,
        /// Byte offset of the payload.
        offset: u64,
    },
}

impl AnomalyKind {
    /// Byte offset of the record this anomaly concerns.
    #[must_use]
    pub fn offset(&self) -> u64 {
        match self {
            Self::CrcMismatch { offset, .. }
            | Self::DeletedRecord { offset, .. }
            | Self::TimestampOutOfOrder { offset, .. }
            | Self::MissingTimestamp { offset, .. } => *offset,
        }
    }

    /// Zero-based record index this anomaly concerns.
    #[must_use]
    pub fn index(&self) -> usize {
        match self {
            Self::CrcMismatch { index, .. }
            | Self::DeletedRecord { index, .. }
            | Self::TimestampOutOfOrder { index, .. }
            | Self::MissingTimestamp { index, .. } => *index,
        }
    }

    fn severity(&self) -> Severity {
        match self {
            Self::CrcMismatch { .. } => Severity::High,
            Self::DeletedRecord { .. } | Self::TimestampOutOfOrder { .. } => Severity::Medium,
            Self::MissingTimestamp { .. } => Severity::Low,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            Self::CrcMismatch { .. } => "SEGB-CRC-MISMATCH",
            Self::DeletedRecord { .. } => "SEGB-RECORD-DELETED",
            Self::TimestampOutOfOrder { .. } => "SEGB-TIMESTAMP-OUT-OF-ORDER",
            Self::MissingTimestamp { .. } => "SEGB-TIMESTAMP-MISSING",
        }
    }

    fn note(&self) -> String {
        match self {
            Self::CrcMismatch { index, stored, computed, .. } => format!(
                "record {index}: stored CRC-32 {stored:#010x} != computed {computed:#010x} \
                 — payload corrupted or edited after write"
            ),
            Self::DeletedRecord { index, .. } => format!(
                "record {index}: logically deleted but still present — recoverable deletion residue"
            ),
            Self::TimestampOutOfOrder { index, prev_unix, this_unix, .. } => format!(
                "record {index}: timestamp {this_unix} precedes prior written record {prev_unix} \
                 — append order broken (clock change or reordering)"
            ),
            Self::MissingTimestamp { index, .. } => {
                format!("record {index}: written record has no finite timestamp")
            }
        }
    }
}

/// An anomaly finding. Construct via [`audit`]; convert to a canonical
/// [`forensicnomicon::report::Finding`] via [`Observation::to_finding`].
#[derive(Debug, Clone, PartialEq)]
pub struct Anomaly {
    /// The specific anomaly and its location.
    pub kind: AnomalyKind,
}

impl Anomaly {
    fn new(kind: AnomalyKind) -> Self {
        Self { kind }
    }

    /// The graded severity of this anomaly.
    #[must_use]
    pub fn severity(&self) -> Severity {
        self.kind.severity()
    }

    /// The published, scheme-prefixed anomaly code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        self.kind.code()
    }
}

impl Observation for Anomaly {
    fn severity(&self) -> Option<Severity> {
        Some(self.kind.severity())
    }

    fn code(&self) -> &'static str {
        self.kind.code()
    }

    fn note(&self) -> String {
        self.kind.note()
    }

    fn evidence(&self) -> Vec<Evidence> {
        vec![Evidence {
            field: "record payload offset".to_string(),
            value: format!("{:#x}", self.kind.offset()),
            location: Some(Location::ByteOffset(self.kind.offset())),
        }]
    }
}

/// Audit a parsed SEGB stream for anomalies.
///
/// Pure and side-effect free: the caller supplies the records already decoded by
/// [`segb::read_segb`]. Walks the records once, tracking the most recent
/// `Written` timestamp to detect append-order violations.
#[must_use]
pub fn audit(records: &[SegbRecord]) -> Vec<Anomaly> {
    // RED stub — no detection yet.
    let _ = records;
    Vec::new()
}
