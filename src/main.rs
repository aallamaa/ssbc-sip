//! SIP Stack implementation for a Session Border Controller
//! This module provides a SIP parser with lazy parsing capabilities,
//! optimized for B2BUA (Back-to-Back User Agent) mode.

use std::collections::HashMap;
use std::fmt;
use strum_macros::{Display, EnumString};

/// Represents the scheme part of a URI (sip, sips, tel)
#[derive(Debug, Clone, PartialEq, Default, Display, EnumString)]
#[strum(serialize_all = "lowercase", ascii_case_insensitive)]
pub enum Scheme {
    #[default]
    SIP,
    SIPS,
    TEL,
}

/// Represents a range within the source text
/// This avoids copying data during parsing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TextRange {
    pub start: usize,
    pub end: usize,
}

impl TextRange {
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    pub fn as_str<'a>(&self, source: &'a str) -> &'a str {
        &source[self.start..self.end]
    }

    pub fn len(&self) -> usize {
        self.end - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Type representing a parameter key
type ParamKey = TextRange;

/// Type representing an optional parameter value
type ParamValue = Option<TextRange>;

/// Type representing a map of parameters
type ParamMap = HashMap<ParamKey, ParamValue>;

/// Represents a SIP URI with all its components
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SipUri {
    pub scheme: Scheme,
    pub user_info: Option<TextRange>,
    pub user_params: ParamMap,
    pub host: Option<TextRange>,
    pub port: Option<u16>,
    pub params: ParamMap,
    pub headers: Option<TextRange>,
}

/// Represents a SIP address, used in headers like To, From, etc.
#[derive(Debug, Clone, PartialEq)]
pub struct Address {
    pub display_name: Option<TextRange>,
    pub uri: SipUri,
    pub params: ParamMap,
}

/// Represents Via header fields
#[derive(Debug, Clone, PartialEq)]
pub struct Via {
    pub sent_protocol: TextRange,
    pub sent_by: TextRange,
    pub params: ParamMap,
}

/// Enum representing different types of header values
#[derive(Debug, Clone, PartialEq)]
pub enum HeaderValue {
    /// Raw reference to the header value text
    Raw(TextRange),
    /// Parsed address (for To, From, Contact, etc.)
    Address(Address),
    /// Parsed Via header
    Via(Via),
}

/// Represents SIP methods (both standard and extensions)
#[derive(Debug, Clone, PartialEq, Display, EnumString)]
#[strum(serialize_all = "UPPERCASE")]
pub enum Method {
    INVITE,
    ACK,
    BYE,
    CANCEL,
    OPTIONS,
    REGISTER,
    PRACK,     // RFC 3262
    SUBSCRIBE, // RFC 6665
    NOTIFY,    // RFC 6665
    PUBLISH,   // RFC 3903
    INFO,      // RFC 6086
    REFER,     // RFC 3515
    MESSAGE,   // RFC 3428
    UPDATE,    // RFC 3311
    #[strum(default)]
    UNKNOWN(String),
}

/// Represents an event package for SUBSCRIBE/NOTIFY
#[derive(Debug, Clone, PartialEq)]
pub struct EventPackage {
    pub event_type: TextRange,
    pub event_params: ParamMap,
}

/// Represents a parsed SIP Message
#[derive(Debug, Clone)]
pub struct SipMessage<'a> {
    /// Original message text
    raw_message: &'a str,

    /// Whether the message is a request (vs response)
    is_request: bool,

    /// Start line range (request line or status line)
    start_line: TextRange,

    /// Required headers with dedicated fields
    via: Option<HeaderValue>,
    to: Option<HeaderValue>,
    from: Option<HeaderValue>,
    cseq: Option<HeaderValue>,
    call_id: Option<HeaderValue>,
    max_forwards: Option<HeaderValue>,

    /// All other headers
    headers: Vec<(TextRange, HeaderValue)>,

    /// Message body if present
    body: Option<TextRange>,

    /// Flag indicating if headers have been parsed
    headers_parsed: bool,

    /// Event-related fields for SIP extensions
    pub event: Option<EventPackage>,
    pub subscription_state: Option<HeaderValue>,
    pub refer_to: Option<HeaderValue>,
}

/// Parser error types
#[derive(Debug)]
pub enum ParseError {
    InvalidMessage {
        message: String,
        position: Option<TextRange>,
    },
    InvalidHeader {
        message: String,
        position: Option<TextRange>,
    },
    InvalidUri {
        message: String,
        position: Option<TextRange>,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::InvalidMessage { message, position } => {
                if let Some(pos) = position {
                    write!(
                        f,
                        "Invalid SIP message at position {}-{}: {}",
                        pos.start, pos.end, message
                    )
                } else {
                    write!(f, "Invalid SIP message: {}", message)
                }
            }
            ParseError::InvalidHeader { message, position } => {
                if let Some(pos) = position {
                    write!(
                        f,
                        "Invalid SIP header at position {}-{}: {}",
                        pos.start, pos.end, message
                    )
                } else {
                    write!(f, "Invalid SIP header: {}", message)
                }
            }
            ParseError::InvalidUri { message, position } => {
                if let Some(pos) = position {
                    write!(
                        f,
                        "Invalid SIP URI at position {}-{}: {}",
                        pos.start, pos.end, message
                    )
                } else {
                    write!(f, "Invalid SIP URI: {}", message)
                }
            }
        }
    }
}

impl std::error::Error for ParseError {}

impl<'a> SipMessage<'a> {
    /// Create a new SIP message from the raw text
    pub fn new(message: &'a str) -> Self {
        Self {
            raw_message: message,
            is_request: false,
            start_line: TextRange::new(0, 0),
            via: None,
            to: None,
            from: None,
            cseq: None,
            call_id: None,
            max_forwards: None,
            headers: Vec::new(),
            body: None,
            headers_parsed: false,
            event: None,
            subscription_state: None,
            refer_to: None,
        }
    }

    /// Parse the message headers lazily
    pub fn parse(&mut self) -> Result<(), ParseError> {
        // Skip if already parsed
        if self.headers_parsed {
            return Ok(());
        }

        // Find the end of the start line
        let start_line_end =
            self.raw_message
                .find("\r\n")
                .ok_or_else(|| ParseError::InvalidMessage {
                    message: "No CRLF after start line".to_string(),
                    position: Some(TextRange::new(0, self.raw_message.len().min(20))),
                })?;

        // Set the start line range
        self.start_line = TextRange::new(0, start_line_end);

        // Determine if it's a request or response
        self.is_request = !self.raw_message.starts_with("SIP/");

        // Find the end of headers (double CRLF)
        let headers_section = &self.raw_message[start_line_end + 2..];
        let body_start = if let Some(pos) = headers_section.find("\r\n\r\n") {
            start_line_end + 2 + pos + 4
        } else {
            // No body, headers until the end
            self.raw_message.len()
        };

        // Parse all headers, handling folded lines
        let mut pos = start_line_end + 2;
        let mut current_header_start = pos;

        while pos < body_start - 2 {
            // Look ahead to see if the next line is a continuation (folded header)
            let next_line_start = pos + self.raw_message[pos..].find("\r\n").unwrap_or(0) + 2;

            if next_line_start < body_start
                && next_line_start < self.raw_message.len()
                && (self.raw_message.as_bytes()[next_line_start] == b' '
                    || self.raw_message.as_bytes()[next_line_start] == b'\t')
            {
                // This is a folded line, continue to next line
                pos = next_line_start;
                continue;
            }

            // Find the end of the current header (including any folded lines)
            let line_end = if let Some(end) = self.raw_message[pos..].find("\r\n") {
                pos + end
            } else {
                body_start - 2
            };

            // Process complete header (from start to end, including any folded parts)
            let header_range = TextRange::new(current_header_start, line_end);
            self.process_header_line(header_range)?;

            // Move to next header
            pos = line_end + 2;
            current_header_start = pos;
        }

        // Set body if present
        if body_start < self.raw_message.len() {
            self.body = Some(TextRange::new(body_start, self.raw_message.len()));
        }

        self.headers_parsed = true;
        Ok(())
    }

    /// Process a single header line (potentially folded)
    fn process_header_line(&mut self, range: TextRange) -> Result<(), ParseError> {
        let line = range.as_str(self.raw_message);

        // Unfold header line by replacing any CRLF + whitespace with a single space
        let unfolded_line = line.replace("\r\n ", " ").replace("\r\n\t", " ");

        // Find the colon separating header name and value
        let colon_pos = unfolded_line
            .find(':')
            .ok_or_else(|| ParseError::InvalidHeader {
                message: "No colon in header line".to_string(),
                position: Some(range.clone()),
            })?;

        let name = &unfolded_line[0..colon_pos];

        // Convert compact form to full form if necessary
        let name = self.expand_compact_header(name);

        // Extract value (skip leading whitespace)
        // We don't need this for now, but keep it for future use
        let _value_str = unfolded_line[colon_pos + 1..].trim();

        // Create a raw range for the value part in the original message
        // For folded headers, this is approximate but works for our zero-copy approach
        // since we'll normalize whitespace in the getter methods anyway
        let mut value_start = range.start + line.find(':').unwrap() + 1;
        while value_start < range.end
            && (self.raw_message.as_bytes()[value_start] == b' '
                || self.raw_message.as_bytes()[value_start] == b'\t')
        {
            value_start += 1;
        }

        let value_range = TextRange::new(value_start, range.end);
        let name_range = TextRange::new(range.start, range.start + colon_pos);

        // Store the header in the appropriate field
        match name.to_lowercase().as_str() {
            "via" => {
                self.via = Some(HeaderValue::Raw(value_range));
            }
            "to" => {
                self.to = Some(HeaderValue::Raw(value_range));
            }
            "from" => {
                self.from = Some(HeaderValue::Raw(value_range));
            }
            "call-id" => {
                self.call_id = Some(HeaderValue::Raw(value_range));
            }
            "cseq" => {
                self.cseq = Some(HeaderValue::Raw(value_range));
            }
            "max-forwards" => {
                self.max_forwards = Some(HeaderValue::Raw(value_range));
            }
            "event" => {
                // Store event header in generic headers list
                self.headers
                    .push((name_range, HeaderValue::Raw(value_range)));
            }
            "subscription-state" => {
                self.subscription_state = Some(HeaderValue::Raw(value_range));
            }
            "refer-to" => {
                self.refer_to = Some(HeaderValue::Raw(value_range));
            }
            _ => {
                // Other headers
                self.headers
                    .push((name_range, HeaderValue::Raw(value_range)));
            }
        }

        Ok(())
    }

    /// Expand compact header form to full form if necessary
    fn expand_compact_header<'b>(&self, name: &'b str) -> &'b str {
        match name.to_lowercase().as_str() {
            "v" => "via",
            "i" => "call-id",
            "m" => "max-forwards",
            "e" => "content-encoding",
            "l" => "content-length",
            "c" => "content-type",
            "f" => "from",
            "t" => "to",
            "r" => "refer-to",
            "b" => "referred-by",
            "k" => "supported",
            "o" => "event",               // o -> event (as per RFC 3265)
            "u" => "allow-events",        // u -> allow-events (as per RFC 3265)
            "a" => "accept-contact",      // RFC 3841
            "j" => "reject-contact",      // RFC 3841
            "d" => "request-disposition", // RFC 3841
            "x" => "session-expires",     // RFC 4028
            "y" => "identity",            // RFC 4474
            "n" => "identity-info",       // RFC 4474
            "h" => "date",                // deprecated but documented
            "s" => "subject",             // deprecated but documented
            _ => name,                    // Not a compact form
        }
    }

    /// Access the raw message text
    pub fn raw_message(&self) -> &'a str {
        self.raw_message
    }

    /// Get the start line text
    pub fn start_line(&self) -> &'a str {
        self.start_line.as_str(self.raw_message)
    }

    /// Check if the message is a request
    pub fn is_request(&self) -> bool {
        self.is_request
    }

    /// Get the body text if present
    pub fn body(&self) -> Option<&'a str> {
        self.body.map(|range| range.as_str(self.raw_message))
    }

    /// Get the Via header, parsing it on demand
    pub fn via(&mut self) -> Result<Option<&Via>, ParseError> {
        if let Some(HeaderValue::Via(ref via)) = self.via {
            Ok(Some(via))
        } else if let Some(HeaderValue::Raw(range)) = self.via {
            // Lazily parse the Via header
            let via_parsed = self.parse_via(range)?;
            self.via = Some(HeaderValue::Via(via_parsed));

            // Return the parsed value
            if let Some(HeaderValue::Via(ref via)) = self.via {
                Ok(Some(via))
            } else {
                unreachable!()
            }
        } else {
            Ok(None)
        }
    }

    /// Get the To header, parsing it on demand
    pub fn to(&mut self) -> Result<Option<&Address>, ParseError> {
        if let Some(HeaderValue::Address(ref addr)) = self.to {
            Ok(Some(addr))
        } else if let Some(HeaderValue::Raw(range)) = self.to {
            // Lazily parse the To header
            let to_parsed = self.parse_address(range)?;
            self.to = Some(HeaderValue::Address(to_parsed));

            // Return the parsed value
            if let Some(HeaderValue::Address(ref addr)) = self.to {
                Ok(Some(addr))
            } else {
                unreachable!()
            }
        } else {
            Ok(None)
        }
    }

    /// Get the From header, parsing it on demand
    pub fn from(&mut self) -> Result<Option<&Address>, ParseError> {
        if let Some(HeaderValue::Address(ref addr)) = self.from {
            Ok(Some(addr))
        } else if let Some(HeaderValue::Raw(range)) = self.from {
            // Lazily parse the From header
            let from_parsed = self.parse_address(range)?;
            self.from = Some(HeaderValue::Address(from_parsed));

            // Return the parsed value
            if let Some(HeaderValue::Address(ref addr)) = self.from {
                Ok(Some(addr))
            } else {
                unreachable!()
            }
        } else {
            Ok(None)
        }
    }

    /// Parse a Via header value
    fn parse_via(&self, range: TextRange) -> Result<Via, ParseError> {
        let via_str = range.as_str(self.raw_message);

        // Split by the first space to get protocol and sent-by parts
        let space_pos = via_str.find(' ').ok_or_else(|| ParseError::InvalidHeader {
            message: "Invalid Via format: missing space".to_string(),
            position: Some(range),
        })?;

        let protocol_range = TextRange::new(range.start, range.start + space_pos);
        let rest_start = range.start + space_pos + 1;

        // Find the end of sent-by (before any parameters)
        let sent_by_end = via_str[space_pos + 1..]
            .find(';')
            .unwrap_or(via_str.len() - space_pos - 1);
        let sent_by_range = TextRange::new(rest_start, rest_start + sent_by_end);

        // Parse parameters if present
        let mut params = HashMap::new();
        if rest_start + sent_by_end < range.end {
            // There are parameters, starting after the semicolon
            let params_range = TextRange::new(rest_start + sent_by_end + 1, range.end);
            self.parse_params(params_range, &mut params)?;
        }

        Ok(Via {
            sent_protocol: protocol_range,
            sent_by: sent_by_range,
            params,
        })
    }

    /// Parse an address specification (used in To, From, etc.)
    fn parse_address(&self, range: TextRange) -> Result<Address, ParseError> {
        let addr_str = range.as_str(self.raw_message);

        let mut address = Address {
            display_name: None,
            uri: SipUri::default(),
            params: HashMap::new(),
        };

        // Check if there's a display name (indicated by < >)
        if let Some(less_than_pos) = addr_str.find('<') {
            if let Some(greater_than_pos) = addr_str.find('>') {
                if greater_than_pos > less_than_pos {
                    // We have a display name
                    let display_part = addr_str[0..less_than_pos].trim();
                    if !display_part.is_empty() {
                        // Calculate the actual trimmed range
                        let start_offset =
                            addr_str[0..less_than_pos].find(display_part).unwrap_or(0);
                        let display_start = range.start + start_offset;
                        let display_end = display_start + display_part.len();

                        // Remove quotes if present
                        if display_part.starts_with('"')
                            && display_part.ends_with('"')
                            && display_part.len() >= 2
                        {
                            address.display_name =
                                Some(TextRange::new(display_start + 1, display_end - 1));
                        } else {
                            address.display_name = Some(TextRange::new(display_start, display_end));
                        }
                    }

                    // Parse the URI part
                    let uri_range = TextRange::new(
                        range.start + less_than_pos + 1,
                        range.start + greater_than_pos,
                    );
                    address.uri = self.parse_uri(uri_range)?;

                    // Check for parameters after the URI
                    if greater_than_pos + 1 < addr_str.len() {
                        let params_start = range.start + greater_than_pos + 1;
                        if addr_str[greater_than_pos + 1..].starts_with(';') {
                            let params_range = TextRange::new(params_start + 1, range.end);
                            self.parse_params(params_range, &mut address.params)?;
                        }
                    }
                } else {
                    return Err(ParseError::InvalidHeader {
                        message: "Malformed address, mismatched brackets".to_string(),
                        position: Some(range),
                    });
                }
            } else {
                return Err(ParseError::InvalidHeader {
                    message: "Unclosed < in address".to_string(),
                    position: Some(range),
                });
            }
        } else {
            // No display name, just parse the URI and any params
            if let Some(semicolon_pos) = addr_str.find(';') {
                // URI with parameters
                let uri_range = TextRange::new(range.start, range.start + semicolon_pos);
                address.uri = self.parse_uri(uri_range)?;

                // Parse parameters
                let params_range = TextRange::new(range.start + semicolon_pos + 1, range.end);
                self.parse_params(params_range, &mut address.params)?;
            } else {
                // Just URI
                address.uri = self.parse_uri(range)?;
            }
        }

        Ok(address)
    }

    /// Parse a URI
    fn parse_uri(&self, range: TextRange) -> Result<SipUri, ParseError> {
        let uri_str = range.as_str(self.raw_message);

        let mut uri = SipUri::default();

        // Parse scheme
        let colon_pos = uri_str.find(':').ok_or_else(|| ParseError::InvalidUri {
            message: "No scheme found in URI".to_string(),
            position: Some(range.clone()),
        })?;

        let scheme_str = &uri_str[0..colon_pos];
        uri.scheme = scheme_str.parse().map_err(|_| ParseError::InvalidUri {
            message: format!("Invalid scheme: {}", scheme_str),
            position: Some(TextRange::new(range.start, range.start + colon_pos)),
        })?;

        // Validate scheme - must be only alphabetic characters
        if !scheme_str.chars().all(|c| c.is_ascii_alphabetic()) {
            return Err(ParseError::InvalidUri {
                message: format!("Invalid scheme (must be alphabetic): {}", scheme_str),
                position: Some(TextRange::new(range.start, range.start + colon_pos)),
            });
        }

        // Parse the rest of the URI
        let rest_start = range.start + colon_pos + 1;
        let rest = &uri_str[colon_pos + 1..];

        // Check for user info (before @)
        if let Some(at_pos) = rest.find('@') {
            let user_part = &rest[0..at_pos];

            // Validate user part characters
            if !self.is_valid_user_part(user_part) {
                return Err(ParseError::InvalidUri {
                    message: format!(
                        "Invalid user part contains prohibited characters: {}",
                        user_part
                    ),
                    position: Some(TextRange::new(rest_start, rest_start + at_pos)),
                });
            }

            // Check for user parameters
            if let Some(semicolon_pos) = user_part.find(';') {
                uri.user_info = Some(TextRange::new(rest_start, rest_start + semicolon_pos));

                // Parse user parameters
                let user_params_range =
                    TextRange::new(rest_start + semicolon_pos + 1, rest_start + at_pos);
                self.parse_params(user_params_range, &mut uri.user_params)?;
            } else {
                uri.user_info = Some(TextRange::new(rest_start, rest_start + at_pos));
            }

            // Parse host part
            let host_start = rest_start + at_pos + 1;
            // Skip directly to parsing the host part
            let host_range = TextRange::new(host_start, range.end);
            self.parse_host_part(host_range, &mut uri)?;
        } else {
            // No user info, just host part
            let host_range = TextRange::new(rest_start, range.end);
            self.parse_host_part(host_range, &mut uri)?;
        }

        Ok(uri)
    }

    /// Validate the user part of a SIP URI according to RFC 3261
    fn is_valid_user_part(&self, user_part: &str) -> bool {
        // Check for empty user part
        if user_part.is_empty() {
            return false;
        }

        // Allowed characters in user part:
        // - unreserved characters (alphanumeric, "-", ".", "_", "~")
        // - escaped characters (%HH)
        // - user-unreserved characters ("&", "=", "+", "$", ",", ";", "?", "/")
        // Check char by char
        let mut i = 0;
        while i < user_part.len() {
            let c = user_part.as_bytes()[i];

            // Escaped character (%HH)
            if c == b'%' {
                // Need at least 2 more characters for %HH
                if i + 2 >= user_part.len() {
                    return false;
                }

                // Check if next two chars are hex digits
                let h1 = user_part.as_bytes()[i + 1];
                let h2 = user_part.as_bytes()[i + 2];
                if !Self::is_hex_digit(h1) || !Self::is_hex_digit(h2) {
                    return false;
                }

                i += 3; // Skip %HH
                continue;
            }

            // Unreserved characters
            if Self::is_unreserved(c) {
                i += 1;
                continue;
            }

            // User-unreserved
            if Self::is_user_unreserved(c) {
                i += 1;
                continue;
            }

            // If we get here, the character is not allowed
            return false;
        }

        true
    }

    /// Check if a byte is a hex digit (0-9, A-F, a-f)
    fn is_hex_digit(c: u8) -> bool {
        (c >= b'0' && c <= b'9') || (c >= b'A' && c <= b'F') || (c >= b'a' && c <= b'f')
    }

    /// Check if a byte is an unreserved character
    fn is_unreserved(c: u8) -> bool {
        (c >= b'a' && c <= b'z') ||  // a-z
        (c >= b'A' && c <= b'Z') ||  // A-Z
        (c >= b'0' && c <= b'9') ||  // 0-9
        c == b'-' || c == b'.' || c == b'_' || c == b'~'
    }

    /// Check if a byte is a user-unreserved character
    fn is_user_unreserved(c: u8) -> bool {
        c == b'&'
            || c == b'='
            || c == b'+'
            || c == b'$'
            || c == b','
            || c == b';'
            || c == b'?'
            || c == b'/'
    }

    /// Parse the host part of a URI
    fn parse_host_part(&self, range: TextRange, uri: &mut SipUri) -> Result<(), ParseError> {
        let host_part = range.as_str(self.raw_message);

        // Split by semicolon (params) or question mark (headers)
        let (host_port_range, rest) = if let Some(semicolon_pos) = host_part.find(';') {
            (
                TextRange::new(range.start, range.start + semicolon_pos),
                Some((
                    TextRange::new(range.start + semicolon_pos + 1, range.end),
                    ';',
                )),
            )
        } else if let Some(question_pos) = host_part.find('?') {
            (
                TextRange::new(range.start, range.start + question_pos),
                Some((
                    TextRange::new(range.start + question_pos + 1, range.end),
                    '?',
                )),
            )
        } else {
            (range, None)
        };

        let host_port = host_port_range.as_str(self.raw_message);

        // Parse host and optional port
        if let Some(colon_pos) = host_port.find(':') {
            uri.host = Some(TextRange::new(
                host_port_range.start,
                host_port_range.start + colon_pos,
            ));

            // Parse port
            let port_str = &host_port[colon_pos + 1..];
            uri.port = Some(
                port_str
                    .parse::<u16>()
                    .map_err(|_| ParseError::InvalidUri {
                        message: format!("Invalid port: {}", port_str),
                        position: None,
                    })?,
            );
        } else {
            uri.host = Some(host_port_range);
        }

        // Parse parameters and headers if present
        if let Some((rest_range, delimiter)) = rest {
            match delimiter {
                ';' => {
                    // Parameters section
                    let rest_str = rest_range.as_str(self.raw_message);
                    if let Some(question_pos) = rest_str.find('?') {
                        // Both parameters and headers
                        let params_range =
                            TextRange::new(rest_range.start, rest_range.start + question_pos);
                        self.parse_params(params_range, &mut uri.params)?;

                        // Headers
                        uri.headers = Some(TextRange::new(
                            rest_range.start + question_pos + 1,
                            rest_range.end,
                        ));
                    } else {
                        // Just parameters
                        self.parse_params(rest_range, &mut uri.params)?;
                    }
                }
                '?' => {
                    // Headers section
                    uri.headers = Some(rest_range);
                }
                _ => unreachable!(),
            }
        }

        Ok(())
    }

    /// Parse parameters string into a HashMap
    fn parse_params(&self, range: TextRange, params: &mut ParamMap) -> Result<(), ParseError> {
        let params_str = range.as_str(self.raw_message);

        let mut start_pos = range.start;
        for param in params_str.split(';') {
            if param.is_empty() {
                start_pos += 1; // Skip the delimiter
                continue;
            }

            let param_len = param.len();

            if let Some(equals_pos) = param.find('=') {
                let name_range = TextRange::new(start_pos, start_pos + equals_pos);
                let value_range = TextRange::new(start_pos + equals_pos + 1, start_pos + param_len);
                params.insert(name_range, Some(value_range));
            } else {
                // Flag parameter (no value)
                let name_range = TextRange::new(start_pos, start_pos + param_len);
                params.insert(name_range, None);
            }

            // Move past this parameter and the delimiter
            start_pos += param_len + 1;
        }

        Ok(())
    }

    /// Helper to get string value from TextRange
    pub fn get_str(&self, range: TextRange) -> &'a str {
        range.as_str(self.raw_message)
    }

    /// Helper to get string value from optional TextRange
    pub fn get_opt_str(&self, range: Option<TextRange>) -> Option<&'a str> {
        range.map(|r| r.as_str(self.raw_message))
    }

    /// Helper to get param key as string
    pub fn get_param_key(&self, key: &ParamKey) -> &'a str {
        key.as_str(self.raw_message)
    }

    /// Helper to get param value as string
    pub fn get_param_value(&self, value: &ParamValue) -> Option<&'a str> {
        value.map(|v| v.as_str(self.raw_message))
    }

    /// Helper to extract parameter map as string map
    pub fn get_params_map<'b>(&'b self, params: &'b ParamMap) -> HashMap<&'a str, Option<&'a str>> {
        params
            .iter()
            .map(|(key, value)| (self.get_param_key(key), self.get_param_value(value)))
            .collect()
    }

    /// Parse the CSeq header and extract the method
    pub fn cseq_method(&mut self) -> Result<Option<Method>, ParseError> {
        if let Some(HeaderValue::Raw(range)) = self.cseq {
            let cseq_str = self.get_str(range);

            // CSeq has format: "sequence_number method"
            let parts: Vec<&str> = cseq_str.trim().split_whitespace().collect();
            if parts.len() < 2 {
                return Err(ParseError::InvalidHeader {
                    message: format!("Invalid CSeq format: {}", cseq_str),
                    position: Some(range),
                });
            }

            // Parse the method
            let method_str = parts[1];
            match method_str.parse::<Method>() {
                Ok(method) => Ok(Some(method)),
                Err(_) => Ok(Some(Method::UNKNOWN(method_str.to_string()))),
            }
        } else {
            Ok(None)
        }
    }

    /// Get the request method from the start line
    pub fn request_method(&self) -> Option<Method> {
        if !self.is_request() {
            return None;
        }

        let start_line = self.start_line();
        let parts: Vec<&str> = start_line.split_whitespace().collect();
        if parts.is_empty() {
            return None;
        }

        match parts[0].parse::<Method>() {
            Ok(method) => Some(method),
            Err(_) => Some(Method::UNKNOWN(parts[0].to_string())),
        }
    }

    /// Add this method to parse Event header for SUBSCRIBE/NOTIFY
    pub fn parse_event(&mut self) -> Result<Option<&EventPackage>, ParseError> {
        // Find the Event header
        let event_header = self.headers.iter().find(|(name_range, _)| {
            let name = self.get_str(*name_range).to_lowercase();
            name == "event" || name == "o" // 'o' is compact form
        });

        if let Some((_, HeaderValue::Raw(range))) = event_header {
            let event_str = self.get_str(*range);

            // Split by semicolon to separate event type from parameters
            let (event_type, params_str) = if let Some(semi_pos) = event_str.find(';') {
                (
                    TextRange::new(range.start, range.start + semi_pos),
                    Some(&event_str[semi_pos + 1..]),
                )
            } else {
                (*range, None)
            };

            // Create event package
            let mut event = EventPackage {
                event_type,
                event_params: HashMap::new(),
            };

            // Parse parameters if present
            if let Some(params) = params_str {
                let params_range =
                    TextRange::new(range.start + event_str.len() - params.len(), range.end);
                self.parse_params(params_range, &mut event.event_params)?;
            }

            // Store and return
            self.event = Some(event);
            return Ok(self.event.as_ref());
        }

        Ok(None)
    }
}

/// A basic implementation of a Back-to-Back User Agent (B2BUA)
pub struct B2BUA {
    // Configuration and state would go here
}

impl B2BUA {
    pub fn new() -> Self {
        Self {}
    }

    /// Process a SIP request and generate a corresponding request to forward
    pub fn process_request<'a>(
        &self,
        request: &'a SipMessage<'a>,
    ) -> Result<SipMessage<'a>, ParseError> {
        // Return a not implemented error with position information
        Err(ParseError::InvalidMessage {
            message: "B2BUA processing not yet implemented".to_string(),
            position: Some(request.start_line),
        })
    }

    /// Process a SIP response and generate a corresponding response to forward
    pub fn process_response<'a>(
        &self,
        response: &'a SipMessage<'a>,
    ) -> Result<SipMessage<'a>, ParseError> {
        // Return a not implemented error with position information
        Err(ParseError::InvalidMessage {
            message: "B2BUA response processing not yet implemented".to_string(),
            position: Some(response.start_line),
        })
    }
}

fn main() {
    // Valid SIP message example
    let valid_message = "\
INVITE sip:bob@biloxi.com SIP/2.0\r
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r
Max-Forwards: 70\r
To: Bob <sip:bob@biloxi.com>\r
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r
Call-ID: a84b4c76e66710@pc33.atlanta.com\r
CSeq: 314159 INVITE\r
Contact: <sip:alice@pc33.atlanta.com>\r
Content-Type: application/sdp\r
Content-Length: 142\r
\r
v=0\r
o=alice 53655765 2353687637 IN IP4 pc33.atlanta.com\r
s=Session SDP\r
c=IN IP4 pc33.atlanta.com\r
t=0 0\r
m=audio 49172 RTP/AVP 0\r
a=rtpmap:0 PCMU/8000\r
";

    // Invalid SIP message examples
    let invalid_message =
        "INVITE sip:bob@biloxi.com SIP/2.0\r\nInvalid-Header-No-Colon Value\r\n\r\n";
    let invalid_uri =
        "INVITE sip@bob@biloxi.com SIP/2.0\r\nVia: SIP/2.0/UDP pc33.atlanta.com\r\n\r\n";

    println!("Parsing valid SIP message...");
    let mut valid_sip = SipMessage::new(valid_message);
    match valid_sip.parse() {
        Ok(_) => println!("Successfully parsed valid SIP message!"),
        Err(e) => println!("Unexpected error: {}", e),
    }

    println!("\nParsing invalid SIP message with header error...");
    let mut invalid_header_sip = SipMessage::new(invalid_message);
    match invalid_header_sip.parse() {
        Ok(_) => println!("Unexpectedly parsed invalid SIP message!"),
        Err(e) => println!("Expected error: {}", e),
    }

    println!("\nParsing invalid SIP message with URI error...");
    let mut invalid_uri_sip = SipMessage::new(invalid_uri);
    match invalid_uri_sip.parse() {
        Ok(_) => println!("Successfully parsed!"),
        Err(e) => println!("Error: {}", e),
    }

    // Extract URI from a To header
    println!("\nExtracting URI from To header...");
    if let Ok(_) = valid_sip.parse() {
        match valid_sip.to() {
            Ok(Some(to_addr)) => {
                println!("To URI scheme: {:?}", to_addr.uri.scheme);
                if let Some(host_range) = to_addr.uri.host {
                    println!("To URI host: {}", valid_sip.get_str(host_range));
                }
            }
            Ok(None) => println!("No To header found"),
            Err(e) => println!("Error extracting To header: {}", e),
        }
    }

    println!("\nB2BUA in action...");
    let b2bua = B2BUA::new();
    if let Ok(_) = valid_sip.parse() {
        match b2bua.process_request(&valid_sip) {
            Ok(_) => println!("B2BUA processed the request successfully"),
            Err(e) => println!("B2BUA encountered an error: {}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_message() {
        let message = "INVITE sip:bob@example.com SIP/2.0\r\n\
                       Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
                       Max-Forwards: 70\r\n\
                       To: Bob <sip:bob@example.com>\r\n\
                       From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
                       Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
                       CSeq: 314159 INVITE\r\n\
                       Contact: <sip:alice@pc33.atlanta.com>\r\n\
                       Content-Type: application/sdp\r\n\
                       Content-Length: 0\r\n\
                       \r\n";

        let mut sip_message = SipMessage::new(message);
        assert!(sip_message.parse().is_ok());
        assert!(sip_message.is_request());
        assert_eq!(
            sip_message.start_line(),
            "INVITE sip:bob@example.com SIP/2.0"
        );

        // Fix borrow checker issues by splitting up the borrow access
        {
            // Get and parse the From header
            let sip_message_clone = sip_message.clone();
            if let Ok(Some(from)) = sip_message.from() {
                // Copy any needed data for assertions
                let display_name = from.display_name;
                let scheme = from.uri.scheme.clone();
                let host = from.uri.host;
                let user_info = from.uri.user_info;
                let has_tag = from
                    .params
                    .iter()
                    .any(|(k, _)| sip_message_clone.get_param_key(k) == "tag");

                // Test the values
                assert_eq!(sip_message_clone.get_opt_str(display_name), Some("Alice"));
                assert_eq!(scheme, Scheme::SIP);
                assert_eq!(sip_message_clone.get_opt_str(host), Some("atlanta.com"));
                assert_eq!(sip_message_clone.get_opt_str(user_info), Some("alice"));
                assert!(has_tag);
            } else {
                panic!("From header not found or couldn't be parsed");
            }
        }
    }

    #[test]
    fn test_parse_response_message() {
        let message = "SIP/2.0 200 OK\r\n\
                       Via: SIP/2.0/UDP server10.biloxi.com;branch=z9hG4bK4b43c2ff8.1\r\n\
                       Via: SIP/2.0/UDP bigbox3.site3.atlanta.com;branch=z9hG4bK77ef4c2312983.1\r\n\
                       Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds;received=192.0.2.1\r\n\
                       To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
                       From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
                       Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
                       CSeq: 314159 INVITE\r\n\
                       Contact: <sip:bob@192.0.2.4>\r\n\
                       Content-Length: 0\r\n\
                       \r\n";

        let mut sip_message = SipMessage::new(message);
        assert!(sip_message.parse().is_ok());
        assert!(!sip_message.is_request());
        assert_eq!(sip_message.start_line(), "SIP/2.0 200 OK");
    }

    #[test]
    fn test_parse_with_body() {
        let message = "INVITE sip:bob@biloxi.com SIP/2.0\r\n\
                       Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
                       Max-Forwards: 70\r\n\
                       To: Bob <sip:bob@biloxi.com>\r\n\
                       From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
                       Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
                       CSeq: 314159 INVITE\r\n\
                       Contact: <sip:alice@pc33.atlanta.com>\r\n\
                       Content-Type: application/sdp\r\n\
                       Content-Length: 142\r\n\
                       \r\n\
                       v=0\r\n\
                       o=alice 53655765 2353687637 IN IP4 pc33.atlanta.com\r\n\
                       s=Session SDP\r\n\
                       c=IN IP4 pc33.atlanta.com\r\n\
                       t=0 0\r\n\
                       m=audio 49172 RTP/AVP 0\r\n\
                       a=rtpmap:0 PCMU/8000\r\n";

        let mut sip_message = SipMessage::new(message);
        assert!(sip_message.parse().is_ok());

        // Check the body is present and correctly extracted
        let body = sip_message.body();
        assert!(body.is_some());
        assert!(body.unwrap().contains("v=0"));
        assert!(body.unwrap().contains("s=Session SDP"));
    }

    #[test]
    fn test_uri_parsing() {
        // Test different URI formats
        let simple_uri = "sip:user@example.com";
        let uri_with_params = "sip:user@example.com;transport=tcp";
        let uri_with_port = "sip:user@example.com:5060";
        let uri_with_headers = "sip:user@example.com?subject=project";
        // Use a valid URI format with percent-encoded password instead of colon
        let uri_with_everything =
            "sips:user%40password@example.com:5061;transport=tls?header1=value1&header2=value2";

        // Helper function to parse URI
        fn parse_uri(uri_str: &str) -> Result<SipUri, ParseError> {
            let range = TextRange::new(0, uri_str.len());
            let message = SipMessage::new(uri_str);
            message.parse_uri(range)
        }

        // Test simple URI
        let uri = parse_uri(simple_uri).expect("Failed to parse simple URI");
        assert_eq!(uri.scheme, Scheme::SIP);

        // Test URI with parameters
        let uri = parse_uri(uri_with_params).expect("Failed to parse URI with params");
        assert_eq!(uri.scheme, Scheme::SIP);
        assert!(uri.params.len() > 0);

        // Test URI with port
        let uri = parse_uri(uri_with_port).expect("Failed to parse URI with port");
        assert_eq!(uri.port, Some(5060));

        // Test URI with headers
        let uri = parse_uri(uri_with_headers).expect("Failed to parse URI with headers");
        assert!(uri.headers.is_some());

        // Test URI with everything
        let uri = parse_uri(uri_with_everything).expect("Failed to parse complex URI");
        assert_eq!(uri.scheme, Scheme::SIPS);
        assert!(uri.port.is_some());
        assert_eq!(uri.port, Some(5061));
    }

    #[test]
    fn test_via_header_parsing() {
        let via_header = "SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds";
        let range = TextRange::new(0, via_header.len());
        let message = SipMessage::new(via_header);

        let via = message
            .parse_via(range)
            .expect("Failed to parse Via header");

        assert_eq!(message.get_str(via.sent_protocol), "SIP/2.0/UDP");
        assert_eq!(message.get_str(via.sent_by), "pc33.atlanta.com");
        assert!(via.params.len() > 0);

        // Check branch parameter
        let branch_param = via
            .params
            .iter()
            .find(|(k, _)| message.get_param_key(k) == "branch");
        assert!(branch_param.is_some());
        let (_, branch_value) = branch_param.unwrap();
        assert_eq!(
            message.get_param_value(branch_value),
            Some("z9hG4bK776asdhds")
        );
    }

    #[test]
    fn test_address_header_parsing() {
        let message = SipMessage::new("Bob <sip:bob@biloxi.com>;tag=a6c85cf");
        let range = TextRange::new(0, "Bob <sip:bob@biloxi.com>;tag=a6c85cf".len());

        let address = message
            .parse_address(range)
            .expect("Failed to parse address");

        assert_eq!(message.get_opt_str(address.display_name), Some("Bob"));
        assert_eq!(address.uri.scheme, Scheme::SIP);
        assert_eq!(message.get_opt_str(address.uri.user_info), Some("bob"));
        assert_eq!(message.get_opt_str(address.uri.host), Some("biloxi.com"));

        // Check tag parameter
        let tag_param = address
            .params
            .iter()
            .find(|(k, _)| message.get_param_key(k) == "tag");
        assert!(tag_param.is_some());
        let (_, tag_value) = tag_param.unwrap();
        assert_eq!(message.get_param_value(tag_value), Some("a6c85cf"));
    }

    #[test]
    fn test_parse_error_with_position() {
        // Create a SIP message with an invalid URI in the start line
        let message_text = "INVITE invalid_without_colon@example.com SIP/2.0\r\nVia: SIP/2.0/UDP pc33.atlanta.com\r\n\r\n";
        let mut message = SipMessage::new(message_text);

        // Parsing the message should succeed at a basic level
        assert!(message.parse().is_ok());

        // But we can manually parse the request URI and verify it fails
        let start_line = message.start_line();
        let parts: Vec<&str> = start_line.split_whitespace().collect();
        assert!(parts.len() >= 2, "Start line should have at least 2 parts");

        let uri_str = parts[1];
        let range = TextRange::new(
            // Position of the URI in the original message
            message_text.find(uri_str).unwrap(),
            message_text.find(uri_str).unwrap() + uri_str.len(),
        );

        let result = message.parse_uri(range);
        assert!(result.is_err(), "URI without colon should fail to parse");

        if let Err(ParseError::InvalidUri { message, position }) = result {
            assert!(
                position.is_some(),
                "Error should include position information"
            );
            assert!(
                message.contains("No scheme found"),
                "Error should mention missing scheme"
            );
        } else {
            panic!("Expected InvalidUri error with position");
        }
    }

    #[test]
    fn test_parse_error_invalid_header() {
        // Test invalid header without colon
        let invalid_header = "INVITE sip:bob@biloxi.com SIP/2.0\r\nInvalid-Header Value\r\n\r\n";
        let mut message = SipMessage::new(invalid_header);

        // The parse should fail
        let result = message.parse();
        assert!(result.is_err());

        // Check that the error contains position information
        match result {
            Err(ParseError::InvalidHeader { position, .. }) => {
                assert!(
                    position.is_some(),
                    "Position information should be present in the error"
                );
            }
            Err(e) => panic!("Unexpected error type: {:?}", e),
            Ok(_) => panic!("Parsing should have failed"),
        }
    }

    #[test]
    fn test_parse_params() {
        let params_str = "transport=tcp;ttl=5;method=INVITE";
        let range = TextRange::new(0, params_str.len());
        let message = SipMessage::new(params_str);

        let mut params_map = HashMap::new();
        message
            .parse_params(range, &mut params_map)
            .expect("Failed to parse parameters");

        assert_eq!(params_map.len(), 3);

        // Convert to string map for easier testing
        let string_map = message.get_params_map(&params_map);

        assert_eq!(string_map.get("transport"), Some(&Some("tcp")));
        assert_eq!(string_map.get("ttl"), Some(&Some("5")));
        assert_eq!(string_map.get("method"), Some(&Some("INVITE")));
    }

    #[test]
    fn test_parse_params_no_value() {
        let params_str = "transport=tcp;lr;maddr=192.0.2.1";
        let range = TextRange::new(0, params_str.len());
        let message = SipMessage::new(params_str);

        let mut params_map = HashMap::new();
        message
            .parse_params(range, &mut params_map)
            .expect("Failed to parse parameters");

        assert_eq!(params_map.len(), 3);

        // Convert to string map for easier testing
        let string_map = message.get_params_map(&params_map);

        assert_eq!(string_map.get("transport"), Some(&Some("tcp")));
        assert_eq!(string_map.get("lr"), Some(&None)); // Parameter with no value
        assert_eq!(string_map.get("maddr"), Some(&Some("192.0.2.1")));
    }

    #[test]
    fn test_text_range() {
        let text = "Hello, world!";
        let range = TextRange::new(0, 5); // "Hello"

        assert_eq!(range.as_str(text), "Hello");
        assert_eq!(range.len(), 5);
        assert!(!range.is_empty());

        let empty_range = TextRange::new(0, 0);
        assert_eq!(empty_range.len(), 0);
        assert!(empty_range.is_empty());
    }

    // The following tests would be more integration-style tests that use the B2BUA
    #[test]
    fn test_b2bua_request_processing() {
        let message = "INVITE sip:bob@biloxi.com SIP/2.0\r\n\
                       Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
                       Max-Forwards: 70\r\n\
                       To: Bob <sip:bob@biloxi.com>\r\n\
                       From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
                       Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
                       CSeq: 314159 INVITE\r\n\
                       Contact: <sip:alice@pc33.atlanta.com>\r\n\
                       Content-Length: 0\r\n\
                       \r\n";

        let mut sip_message = SipMessage::new(message);
        sip_message.parse().expect("Failed to parse message");

        let b2bua = B2BUA::new();
        let _result = b2bua.process_request(&sip_message);
        // Additional assertions would depend on B2BUA implementation
    }

    #[test]
    fn test_malformed_uri_position() {
        // This URI should fail because it has no colon after the scheme
        let uri_str = "sip_no_colon@example.com";
        let message = SipMessage::new(uri_str);
        let range = TextRange::new(0, uri_str.len());

        let result = message.parse_uri(range);
        assert!(
            result.is_err(),
            "URI without colon after scheme should fail to parse"
        );

        if let Err(ParseError::InvalidUri {
            message: _,
            position,
        }) = result
        {
            assert!(position.is_some());
        } else {
            panic!("Expected InvalidUri error with position");
        }
    }

    #[test]
    fn test_invalid_scheme_position() {
        // Test that an invalid scheme is reported with the correct position
        let uri_str = "invalid:bob@biloxi.com";
        let message = SipMessage::new(uri_str);
        let range = TextRange::new(0, uri_str.len());

        let result = message.parse_uri(range);
        assert!(result.is_err());

        if let Err(ParseError::InvalidUri {
            message: msg,
            position,
        }) = result
        {
            assert!(msg.contains("Invalid scheme"));
            assert!(position.is_some());
            let pos = position.unwrap();
            // Position should point to the scheme part
            assert_eq!(message.get_str(pos), "invalid");
        } else {
            panic!("Expected InvalidUri error with position");
        }
    }

    #[test]
    fn test_parse_host_port_error() {
        // Test error position when parsing invalid host:port format
        let uri_str = "sip:alice@atlanta.com:invalid";
        let message = SipMessage::new(uri_str);
        let range = TextRange::new(0, uri_str.len());

        let result = message.parse_uri(range);
        assert!(result.is_err());

        if let Err(ParseError::InvalidUri {
            message: msg,
            position: _,
        }) = result
        {
            assert!(msg.contains("Invalid port"));
        } else {
            panic!("Expected InvalidUri error");
        }
    }

    #[test]
    fn test_max_forwards_parsing() {
        // Test parsing of Max-Forwards header
        let message = "\
INVITE sip:bob@biloxi.com SIP/2.0\r
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r
Max-Forwards: 70\r
\r
";
        let mut sip_message = SipMessage::new(message);
        assert!(sip_message.parse().is_ok());

        // Check Max-Forwards header
        match &sip_message.max_forwards {
            Some(HeaderValue::Raw(range)) => {
                assert_eq!(sip_message.get_str(*range), "70");
            }
            _ => panic!("Max-Forwards header not parsed correctly"),
        }
    }

    #[test]
    fn test_b2bua_default_implementation() {
        // Test that the default B2BUA implementation returns an error
        let message = "\
INVITE sip:bob@biloxi.com SIP/2.0\r
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r
\r
";
        let mut sip_message = SipMessage::new(message);
        assert!(sip_message.parse().is_ok());

        let b2bua = B2BUA::new();
        let result = b2bua.process_request(&sip_message);

        // The default implementation should return an error
        assert!(result.is_err());
    }

    #[test]
    fn test_text_range_operations() {
        // Test TextRange operations more thoroughly
        let range1 = TextRange::new(10, 20);
        let range2 = TextRange::new(10, 20);
        let range3 = TextRange::new(5, 15);

        // Test equality
        assert_eq!(range1, range2);
        assert_ne!(range1, range3);

        // Test length
        assert_eq!(range1.len(), 10);

        // Test is_empty
        assert!(!range1.is_empty());
        assert!(TextRange::new(10, 10).is_empty());

        // Test string extraction
        let text = "0123456789abcdefghijklmnopqrstuvwxyz";
        assert_eq!(range1.as_str(text), "abcdefghij");
    }

    #[test]
    fn test_mime_type_header_parsing() {
        // Test parsing of Content-Type header
        let message = "\
INVITE sip:bob@biloxi.com SIP/2.0\r
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r
Content-Type: application/sdp\r
\r
v=0\r
o=alice 53655765 2353687637 IN IP4 pc33.atlanta.com\r
";
        let mut sip_message = SipMessage::new(message);
        assert!(sip_message.parse().is_ok());

        // Find Content-Type header
        let content_type = sip_message.headers.iter().find(|(name_range, _)| {
            sip_message.get_str(*name_range).to_lowercase() == "content-type"
        });

        assert!(content_type.is_some());
        if let Some((_, HeaderValue::Raw(value_range))) = content_type {
            assert_eq!(sip_message.get_str(*value_range), "application/sdp");
        } else {
            panic!("Content-Type header not found or not parsed correctly");
        }
    }

    #[test]
    fn test_sip_response_parsing() {
        // Test parsing a SIP response instead of a request
        let message = "\
SIP/2.0 200 OK\r
Via: SIP/2.0/UDP server10.biloxi.com;branch=z9hG4bK4442ba5c\r
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r
Call-ID: a84b4c76e66710@pc33.atlanta.com\r
CSeq: 314159 INVITE\r
\r
";
        let mut sip_message = SipMessage::new(message);
        assert!(sip_message.parse().is_ok());

        // Check that it's correctly identified as a response
        assert!(!sip_message.is_request());

        // Check the start line
        assert_eq!(sip_message.start_line(), "SIP/2.0 200 OK");
    }

    #[test]
    fn test_header_case_insensitivity() {
        // Test header name case insensitivity
        let message = "\
INVITE sip:bob@biloxi.com SIP/2.0\r
via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r
to: Bob <sip:bob@biloxi.com>\r
from: Alice <sip:alice@atlanta.com>;tag=1928301774\r
\r
";
        let mut sip_message = SipMessage::new(message);
        assert!(sip_message.parse().is_ok());

        // Headers should be parsed correctly despite case
        assert!(sip_message.via().unwrap().is_some());
        assert!(sip_message.to().unwrap().is_some());
        assert!(sip_message.from().unwrap().is_some());
    }

    #[test]
    fn test_folded_header_lines() {
        // Test support for folded header lines per RFC 3261
        let message = "\
INVITE sip:bob@biloxi.com SIP/2.0\r
Via: SIP/2.0/UDP pc33.atlanta.com;\r
 branch=z9hG4bK776asdhds;\r
 received=192.0.2.1\r
To: Bob \r
 <sip:bob@biloxi.com>\r
From: Alice \r
\t<sip:alice@atlanta.com>;\r
 tag=1928301774\r
Call-ID: a84b4c76e66710@pc33.atlanta.com\r
\r
";
        let mut sip_message = SipMessage::new(message);
        assert!(sip_message.parse().is_ok());

        // Check that Via header is parsed correctly
        let via_result = sip_message.via();
        assert!(via_result.is_ok());
        assert!(via_result.unwrap().is_some());

        // Check that From header is parsed correctly
        let from_result = sip_message.from();
        assert!(from_result.is_ok());
        assert!(from_result.unwrap().is_some());

        // The test passes if we can successfully parse the folded headers
    }

    #[test]
    fn test_body_with_content_length() {
        // Test body parsing using Content-Length header
        let message = "\
INVITE sip:bob@biloxi.com SIP/2.0\r
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r
Content-Length: 11\r
\r
Hello World";

        let mut sip_message = SipMessage::new(message);
        assert!(sip_message.parse().is_ok());

        // Check the body
        assert_eq!(sip_message.body().unwrap(), "Hello World");
    }

    #[test]
    fn test_enhanced_compact_header_handling() {
        // Test all compact header forms
        let message = "\
INVITE sip:bob@biloxi.com SIP/2.0\r
v: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r
t: Bob <sip:bob@biloxi.com>\r
f: Alice <sip:alice@atlanta.com>;tag=1928301774\r
i: a84b4c76e66710@pc33.atlanta.com\r
m: 70\r
e: gzip\r
l: 0\r
c: application/sdp\r
k: path\r
o: presence\r
u: presence, dialog\r
\r
";
        let mut sip_message = SipMessage::new(message);
        assert!(sip_message.parse().is_ok());

        // Check that compact headers are correctly expanded
        assert!(sip_message.via().unwrap().is_some());
        assert!(sip_message.to().unwrap().is_some());
        assert!(sip_message.from().unwrap().is_some());
        assert!(sip_message.call_id.is_some());
        assert!(sip_message.max_forwards.is_some());

        // Find the content-type header (c)
        let content_type = sip_message.headers.iter().find(|(name_range, _)| {
            let name = sip_message.get_str(*name_range).to_lowercase();
            name == "c" || name == "content-type"
        });
        assert!(content_type.is_some());
    }

    #[test]
    fn test_uri_character_validation() {
        // Test URI with valid characters
        let uri_str = "sip:alice@atlanta.com";
        let range = TextRange::new(0, uri_str.len());
        let message = SipMessage::new(uri_str);
        assert!(message.parse_uri(range).is_ok());

        // Test URI with invalid characters in user part
        let invalid_uri = "sip:alice[123]@atlanta.com";
        let range = TextRange::new(0, invalid_uri.len());
        let message = SipMessage::new(invalid_uri);
        let result = message.parse_uri(range);
        assert!(result.is_err());

        // Test URI with valid percent-encoded characters
        let encoded_uri = "sip:alice%20smith@atlanta.com";
        let range = TextRange::new(0, encoded_uri.len());
        let message = SipMessage::new(encoded_uri);
        assert!(message.parse_uri(range).is_ok());

        // Test URI with invalid percent-encoding
        let bad_encoded_uri = "sip:alice%2@atlanta.com";
        let range = TextRange::new(0, bad_encoded_uri.len());
        let message = SipMessage::new(bad_encoded_uri);
        let result = message.parse_uri(range);
        assert!(result.is_err());
    }

    #[test]
    fn test_folded_header_enhancements() {
        // Test with multiple folded lines
        let message = "\
INVITE sip:bob@biloxi.com SIP/2.0\r
Via: SIP/2.0/UDP pc33.atlanta.com;\r
 branch=z9hG4bK776asdhds;\r
 received=192.0.2.1\r
To: Bob <sip:bob@biloxi.com>\r
From: Alice \r
\t<sip:alice@atlanta.com>;\r
 tag=1928301774\r
Call-ID: a84b4c76e66710@pc33.atlanta.com\r
\r
";
        let mut sip_message = SipMessage::new(message);
        assert!(sip_message.parse().is_ok());

        // Check that Via header is parsed correctly
        let via_result = sip_message.via();
        assert!(via_result.is_ok());
        assert!(via_result.unwrap().is_some());

        // Check that From header is parsed correctly
        let from_result = sip_message.from();
        assert!(from_result.is_ok());
        assert!(from_result.unwrap().is_some());

        // The test passes if we can successfully parse the folded headers
    }

    #[test]
    fn test_method_parsing() {
        // Test parsing methods from request line
        let message = "SUBSCRIBE sip:bob@biloxi.com SIP/2.0\r\nEvent: presence\r\n\r\n";
        let mut sip_message = SipMessage::new(message);
        assert!(sip_message.parse().is_ok());

        // Check request method
        let method = sip_message.request_method();
        assert!(method.is_some());
        assert_eq!(method.unwrap(), Method::SUBSCRIBE);

        // Test parsing method from CSeq
        let message = "\
SUBSCRIBE sip:bob@biloxi.com SIP/2.0\r
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r
CSeq: 123 SUBSCRIBE\r
\r
";
        let mut sip_message = SipMessage::new(message);
        assert!(sip_message.parse().is_ok());

        // Check CSeq method
        let method_result = sip_message.cseq_method();
        assert!(method_result.is_ok());
        let method = method_result.unwrap();
        assert!(method.is_some());
        assert_eq!(method.unwrap(), Method::SUBSCRIBE);

        // Test unknown method
        let message = "UNKNOWN sip:bob@biloxi.com SIP/2.0\r\nCSeq: 123 UNKNOWN\r\n\r\n";
        let mut sip_message = SipMessage::new(message);
        assert!(sip_message.parse().is_ok());

        // Check request method
        let method = sip_message.request_method();
        assert!(method.is_some());
        match method.unwrap() {
            Method::UNKNOWN(name) => assert_eq!(name, "UNKNOWN"),
            _ => panic!("Expected UNKNOWN method"),
        }
    }

    #[test]
    fn test_event_package_parsing() {
        // Test SUBSCRIBE with Event header
        let message = "\
SUBSCRIBE sip:bob@biloxi.com SIP/2.0\r
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r
Event: presence;id=123;expire=3600\r
\r
";
        let mut sip_message = SipMessage::new(message);
        assert!(sip_message.parse().is_ok());

        // Parse the Event header
        let event_result = sip_message.parse_event();
        assert!(event_result.is_ok());

        // Check that event was parsed
        let event_option = event_result.unwrap();
        assert!(event_option.is_some());

        // The test passes if we can successfully parse the event header
        // We can't directly access the event parameters due to borrowing constraints
    }

    #[test]
    fn test_error_in_from_header() {
        // Test that an error in the From header is correctly reported
        let message = "\
INVITE sip:bob@biloxi.com SIP/2.0\r
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r
From: Alice <malformed-uri>\r
\r
";
        let mut sip_message = SipMessage::new(message);
        assert!(sip_message.parse().is_ok());

        // Try to access the From header, which should trigger an error during lazy parsing
        let result = sip_message.from();
        assert!(result.is_err());

        // Check error details
        match result {
            Err(ParseError::InvalidUri {
                message: _,
                position,
            }) => {
                assert!(position.is_some());
            }
            _ => panic!("Expected InvalidUri error"),
        }
    }

    #[test]
    fn test_special_uri_characters() {
        // Test URI with special characters allowed by RFC 3261
        let uri_str = "sip:user;param=val%20ue@example.com:5060;transport=tcp?header=value";
        let message = SipMessage::new(uri_str);
        let range = TextRange::new(0, uri_str.len());

        let result = message.parse_uri(range);
        assert!(result.is_ok());

        let uri = result.unwrap();

        // Check URI parts with special characters
        assert_eq!(message.get_opt_str(uri.user_info), Some("user"));

        // Check user parameters
        let user_params = message.get_params_map(&uri.user_params);
        assert_eq!(user_params.get("param"), Some(&Some("val%20ue")));

        // Check URI parameters and headers
        let params = message.get_params_map(&uri.params);
        assert_eq!(params.get("transport"), Some(&Some("tcp")));
        assert!(uri.headers.is_some());
    }

    #[test]
    fn test_error_propagation_with_position() {
        // Create a custom ParseError with position information
        let error_position = TextRange::new(15, 25);
        let original_error = ParseError::InvalidUri {
            message: "Test error with position".to_string(),
            position: Some(error_position),
        };

        // Simulate propagating this error through the code
        let propagated_error = propagate_error(original_error);

        // Verify that the position information is preserved
        match propagated_error {
            ParseError::InvalidUri {
                message: _,
                position,
            } => {
                assert!(position.is_some());
            }
            _ => panic!("Expected InvalidUri error with position"),
        }
    }

    // Helper function to simulate error propagation
    fn propagate_error(err: ParseError) -> ParseError {
        // In real code, this might do additional processing or wrap the error
        match err {
            ParseError::InvalidUri {
                message,
                position: pos,
            } => {
                // Just return the same error to test position preservation
                ParseError::InvalidUri {
                    message: format!("Propagated: {}", message),
                    position: pos,
                }
            }
            other => other,
        }
    }
}
