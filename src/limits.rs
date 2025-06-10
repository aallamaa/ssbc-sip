//! Security limits and constants for SSBC
//! 
//! These limits prevent DoS attacks while maintaining RFC compliance

/// Maximum SIP message size we'll accept (64KB - 1)
/// This matches our u16 TextRange optimization
pub const MAX_MESSAGE_SIZE: usize = 65535;

/// Maximum number of headers in a single message
pub const MAX_HEADERS: usize = 256;

/// Maximum length of a single header line (including folding)
pub const MAX_HEADER_LINE_LENGTH: usize = 8192;

/// Maximum depth for URI parsing recursion
pub const MAX_URI_PARSE_DEPTH: usize = 10;

/// Maximum number of parameters per header
pub const MAX_HEADER_PARAMS: usize = 32;

/// Maximum number of Via headers (hops)
pub const MAX_VIA_HEADERS: usize = 70;  // RFC 3261 recommends 70

/// Maximum CSeq number value
pub const MAX_CSEQ: u32 = 2_147_483_647;  // 2^31 - 1

/// Minimum session timer value (RFC 4028)
pub const MIN_SESSION_EXPIRES: u32 = 90;

/// Maximum number of concurrent transactions
pub const MAX_TRANSACTIONS: usize = 10_000;

/// Maximum number of concurrent calls
pub const MAX_CONCURRENT_CALLS: usize = 50_000;