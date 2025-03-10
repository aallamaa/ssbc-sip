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

        // Parse all headers
        let mut pos = start_line_end + 2;
        while pos < body_start - 2 {
            // Find the end of the current header line
            let line_end = if let Some(end) = self.raw_message[pos..].find("\r\n") {
                pos + end
            } else {
                break;
            };

            // Check for header folding (continuation lines)
            let mut header_end = line_end;
            let mut next_pos = line_end + 2;

            while next_pos < body_start - 2 {
                // Check if the next line is a continuation (starts with space or tab)
                if next_pos < self.raw_message.len()
                    && (self.raw_message.as_bytes()[next_pos] == b' '
                        || self.raw_message.as_bytes()[next_pos] == b'\t')
                {
                    // Find the end of this continuation line
                    if let Some(cont_end) = self.raw_message[next_pos..].find("\r\n") {
                        header_end = next_pos + cont_end;
                        next_pos = header_end + 2;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }

            // Process the complete header (including any folded lines)
            self.process_header_line(TextRange::new(pos, header_end))?;

            // Move to the next header
            pos = next_pos;
        }

        // Set body if present
        if body_start < self.raw_message.len() {
            self.body = Some(TextRange::new(body_start, self.raw_message.len()));
        }

        self.headers_parsed = true;
        Ok(())
    }

    /// Process a single header line
    fn process_header_line(&mut self, range: TextRange) -> Result<(), ParseError> {
        let line = range.as_str(self.raw_message);

        // Find the colon separating header name and value
        let colon_pos = line.find(':').ok_or_else(|| ParseError::InvalidHeader {
            message: "No colon in header line".to_string(),
            position: Some(range),
        })?;

        let name_range = TextRange::new(range.start, range.start + colon_pos);
        let name = name_range.as_str(self.raw_message);

        // Extract value (skip leading whitespace)
        let mut value_start = range.start + colon_pos + 1;
        while value_start < range.end
            && (self.raw_message.as_bytes()[value_start] == b' '
                || self.raw_message.as_bytes()[value_start] == b'\t')
        {
            value_start += 1;
        }

        let value_range = TextRange::new(value_start, range.end);

        // Store in the appropriate field based on header name
        match name.to_lowercase().as_str() {
            "via" | "v" => {
                self.via = Some(HeaderValue::Raw(value_range));
            }
            "to" | "t" => {
                self.to = Some(HeaderValue::Raw(value_range));
            }
            "from" | "f" => {
                self.from = Some(HeaderValue::Raw(value_range));
            }
            "call-id" | "i" => {
                self.call_id = Some(HeaderValue::Raw(value_range));
            }
            "cseq" => {
                self.cseq = Some(HeaderValue::Raw(value_range));
            }
            "max-forwards" => {
                self.max_forwards = Some(HeaderValue::Raw(value_range));
            }
            _ => {
                // Other headers
                self.headers
                    .push((name_range, HeaderValue::Raw(value_range)));
            }
        }

        Ok(())
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
            position: Some(range),
        })?;

        let scheme_str = &uri_str[0..colon_pos];
        uri.scheme = scheme_str.parse().map_err(|_| ParseError::InvalidUri {
            message: format!("Invalid scheme: {}", scheme_str),
            position: Some(TextRange::new(range.start, range.start + colon_pos)),
        })?;

        // Parse the rest of the URI
        let rest_start = range.start + colon_pos + 1;
        let rest = &uri_str[colon_pos + 1..];

        // Check for user info (before @)
        if let Some(at_pos) = rest.find('@') {
            let user_part = &rest[0..at_pos];

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
        _request: &'a SipMessage<'a>,
    ) -> Result<SipMessage<'a>, ParseError> {
        // This would include logic to modify headers, change routing information, etc.
        // For now, just a placeholder
        todo!("Implement B2BUA request processing")
    }

    /// Process a SIP response and generate a corresponding response to forward
    pub fn process_response<'a>(
        &self,
        _response: &'a SipMessage<'a>,
    ) -> Result<SipMessage<'a>, ParseError> {
        // This would include logic to modify headers, change routing information, etc.
        // For now, just a placeholder
        todo!("Implement B2BUA response processing")
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
}
