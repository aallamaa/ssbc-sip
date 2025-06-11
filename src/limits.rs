// Security limits for SIP parsing to prevent DoS attacks

/// Maximum allowed size for a complete SIP message
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; // 64MB

/// Maximum allowed length for a single header line
pub const MAX_HEADER_LINE_LENGTH: usize = 8192; // 8KB

/// Maximum allowed number of headers in a message
pub const MAX_HEADERS: usize = 256;

/// Maximum allowed length for a header name
pub const MAX_HEADER_NAME_LENGTH: usize = 128;

/// Maximum allowed length for a header value
pub const MAX_HEADER_VALUE_LENGTH: usize = 8192; // 8KB

/// Maximum allowed depth for URI parsing (to prevent stack overflow)
pub const MAX_URI_DEPTH: usize = 10;

/// Maximum allowed length for a URI
pub const MAX_URI_LENGTH: usize = 2048;

/// Maximum allowed parameters per header
pub const MAX_HEADER_PARAMS: usize = 32;

/// Maximum allowed length for the start line (request/response line)
pub const MAX_START_LINE_LENGTH: usize = 8192; // 8KB

/// Maximum allowed body size
pub const MAX_BODY_SIZE: usize = 16 * 1024 * 1024; // 16MB

/// Configuration for parser limits
#[derive(Debug, Clone)]
pub struct ParserLimits {
    pub max_message_size: usize,
    pub max_header_line_length: usize,
    pub max_headers: usize,
    pub max_header_name_length: usize,
    pub max_header_value_length: usize,
    pub max_uri_depth: usize,
    pub max_uri_length: usize,
    pub max_header_params: usize,
    pub max_start_line_length: usize,
    pub max_body_size: usize,
}

impl Default for ParserLimits {
    fn default() -> Self {
        Self {
            max_message_size: MAX_MESSAGE_SIZE,
            max_header_line_length: MAX_HEADER_LINE_LENGTH,
            max_headers: MAX_HEADERS,
            max_header_name_length: MAX_HEADER_NAME_LENGTH,
            max_header_value_length: MAX_HEADER_VALUE_LENGTH,
            max_uri_depth: MAX_URI_DEPTH,
            max_uri_length: MAX_URI_LENGTH,
            max_header_params: MAX_HEADER_PARAMS,
            max_start_line_length: MAX_START_LINE_LENGTH,
            max_body_size: MAX_BODY_SIZE,
        }
    }
}

impl ParserLimits {
    /// Create parser limits suitable for high-security environments
    pub fn strict() -> Self {
        Self {
            max_message_size: 1024 * 1024,        // 1MB
            max_header_line_length: 2048,         // 2KB
            max_headers: 64,
            max_header_name_length: 64,
            max_header_value_length: 2048,        // 2KB
            max_uri_depth: 5,
            max_uri_length: 512,
            max_header_params: 16,
            max_start_line_length: 2048,          // 2KB
            max_body_size: 512 * 1024,            // 512KB
        }
    }
    
    /// Create parser limits suitable for carrier-grade deployments
    pub fn carrier_grade() -> Self {
        Self {
            max_message_size: 10 * 1024 * 1024,   // 10MB
            max_header_line_length: 4096,         // 4KB
            max_headers: 128,
            max_header_name_length: 128,
            max_header_value_length: 4096,        // 4KB
            max_uri_depth: 8,
            max_uri_length: 1024,
            max_header_params: 24,
            max_start_line_length: 4096,          // 4KB
            max_body_size: 5 * 1024 * 1024,       // 5MB
        }
    }
}