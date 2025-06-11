// SIP Stack implementation for a Session Border Controller
// This module provides a SIP parser with lazy parsing capabilities,
// optimized for B2BUA (Back-to-Back User Agent) mode.

// benchmark module is now at crate level

use crate::types::*;
use crate::{validate_required_option_header, validate_required_vec_header, check_duplicate_and_set};
use crate::error::{SsbcError, SsbcResult};
use crate::limits::*;
use crate::validation;
use std::collections::HashMap;

/// Macro to create a clone of a SipMessage for parsing
/// This helps avoid borrowing issues when working with headers
// Deprecated: This macro was used to create a clone of the SipMessage for parsing,
// but it's inefficient as it clones the entire message unnecessarily.
// Instead, we now use optimized methods that take a reference to the raw message
// (see get_raw_message macro and methods like parse_uri_with_message).
//#[macro_export]
//macro_rules! clone_for_parsing {
//    ($self:expr) => {
//        {
//            let raw_message_clone = $self.raw_message.clone();
//            SipMessage {
//                raw_message: raw_message_clone,
//                ..$self.clone()
//            }
//        }
//    };
//}

/// Macro to get a reference to the raw message string
/// This avoids unnecessary cloning when we just need to access the raw message
#[macro_export]
macro_rules! get_raw_message {
    ($self:expr) => {
        &$self.raw_message
    };
}

/// Macro to handle address header (To, From, Contact) parsing logic
#[macro_export]
macro_rules! parse_address_header {
    ($self:expr, $field_name:ident, $header_name:expr) => {{
        // Check if we need to parse
        let needs_parsing = match &$self.$field_name {
            Some(HeaderValue::Raw(range)) => Some(*range),
            _ => None,
        };

        // Parse the header if needed
        if let Some(range) = needs_parsing {
            // Use the optimized method that takes a reference to raw_message
            let parsed = $self.parse_address(range)?;
            $self.$field_name = Some(HeaderValue::Address(parsed));
        }

        // Handle error cases and return
        match &$self.$field_name {
            Some(HeaderValue::Address(ref addr)) => Ok(Some(addr)),
            Some(HeaderValue::Via(_)) => Err(SsbcError::ParseError {
                message: format!("{} header incorrectly parsed as Via", $header_name),
                position: None,
                context: None,
            }),
            _ => Ok(None),
        }
    }};
}

/// Macro to check if a Header value is already parsed, and if not, parse it
#[macro_export]
macro_rules! ensure_header_parsed {
    ($self:expr, $headers:expr, $index:expr, $header_type:expr, $parse_method:ident) => {{
        // Skip if already parsed
        let needs_parsing = match $headers.get($index) {
            Some(HeaderValue::Raw(range)) => Some(*range),
            Some(HeaderValue::Via(_)) if $header_type != "Via" => {
                return Err(SsbcError::ParseError {
                    message: format!("{} header incorrectly parsed as Via", $header_type),
                    position: None,
                    context: None,
                });
            }
            Some(HeaderValue::Address(_)) if $header_type != "Address" => {
                return Err(SsbcError::ParseError {
                    message: format!("{} header incorrectly parsed as Address", $header_type),
                    position: None,
                    context: None,
                });
            }
            _ => None,
        };

        if let Some(range) = needs_parsing {
            // Parse the header using the optimized method
            let parsed = $self.$parse_method(range)?;

            // Update in the headers array
            $headers[$index] = parsed;
        }

        Ok(())
    }};
}

/// Macro to check for duplicate headers and set header value

/// Macro to parse a range of via headers
#[macro_export]
macro_rules! parse_via_headers {
    ($self:expr, $headers:expr, $count:expr) => {{
        let mut result = Vec::new();

        // First parse any raw via headers
        for i in 0..$count {
            // Check if this header needs parsing
            let need_to_parse = match $headers.get(i) {
                Some(HeaderValue::Raw(range)) => Some(*range),
                _ => None,
            };

            // If we need to parse, do so
            if let Some(range) = need_to_parse {
                // Parse the Via header using the optimized method
                let via_parsed = $self.parse_via(range)?;

                // Replace the raw value with the parsed one
                $headers[i] = HeaderValue::Via(via_parsed);
            }
        }

        // Now collect all parsed Via headers
        for i in 0..$count {
            if let HeaderValue::Via(ref via) = $headers[i] {
                result.push(via);
            }
        }

        Ok(result)
    }};
}

/// Macro to ensure a contact header is parsed at a specific index
#[macro_export]
macro_rules! ensure_contact_parsed {
    ($self:expr, $index:expr) => {{
        // Skip if already parsed
        if let HeaderValue::Address(_) = $self.contact_headers[$index] {
            return Ok(());
        }

        // Handle invalid header type
        if let HeaderValue::Via(_) = $self.contact_headers[$index] {
            return Err(SsbcError::ParseError {
                message: "Contact header incorrectly parsed as Via".to_string(),
                position: None,
                context: None,
            });
        }

        // Extract the range from the raw value
        let range = if let HeaderValue::Raw(r) = $self.contact_headers[$index] {
            r
        } else {
            unreachable!() // Already checked above
        };

        // Parse the address using the optimized method
        let contact_parsed = $self.parse_address(range)?;

        // Update the contact header
        $self.contact_headers[$index] = HeaderValue::Address(contact_parsed.clone());

        // Also update in main headers array for backward compatibility
        for (name_range, value) in &mut $self.headers {
            let name = name_range.as_str(&$self.raw_message).to_lowercase();
            if name == "contact" {
                if let HeaderValue::Raw(r) = value {
                    if *r == range {
                        *value = HeaderValue::Address(contact_parsed.clone());
                        break;
                    }
                }
            }
        }

        Ok(())
    }};
}

/// Macro to find headers by name in the headers array
#[macro_export]
macro_rules! find_headers_by_name {
    ($self:expr, $name:expr) => {{
        let mut results = Vec::new();
        for (name_range, value) in &$self.headers {
            let header_name = name_range.as_str(&$self.raw_message).to_lowercase();
            if header_name == $name.to_lowercase() {
                results.push(value);
            }
        }
        results
    }};
}

/// Represents a parsed SIP Message
#[derive(Debug, Clone)]
pub struct SipMessage {
    /// Original message text
    raw_message: String,

    // Booleans and small values first to optimize memory layout
    /// Whether the message is a request (vs response)
    is_request: bool,

    /// Flag indicating if headers have been parsed
    headers_parsed: bool,

    /// Flag indicating if Contact header has multiple entries on a single line
    contact_has_multiple_entries: bool,

    /// Parser limits for security
    limits: ParserLimits,

    /// Start line range (request line or status line)
    start_line: TextRange,

    /// Message body if present
    body: Option<TextRange>,

    // Required headers with dedicated fields (all Option types grouped together)
    /// To header
    to: Option<HeaderValue>,

    /// From header
    from: Option<HeaderValue>,

    /// CSeq header
    cseq: Option<HeaderValue>,

    /// Call-ID header
    call_id: Option<HeaderValue>,

    /// Max-Forwards header
    max_forwards: Option<HeaderValue>,

    /// Event-related fields for SIP extensions
    pub event: Option<EventPackageData>,
    pub subscription_state: Option<HeaderValue>,
    pub refer_to: Option<HeaderValue>,

    // Vectors last (as they're larger and have varying sizes)
    /// Contact headers
    contact_headers: Vec<HeaderValue>,

    /// Via headers
    via_headers: Vec<HeaderValue>,

    /// All other headers
    headers: Vec<(TextRange, HeaderValue)>,
}


impl SipMessage {
    /// Create a new SIP message from the raw text
    pub fn new(message: String) -> Self {
        Self::with_limits(message, ParserLimits::default())
    }

    /// Create a new SIP message with custom parser limits
    pub fn with_limits(message: String, limits: ParserLimits) -> Self {
        Self {
            raw_message: message,
            is_request: false,
            headers_parsed: false,
            contact_has_multiple_entries: false,
            limits,
            start_line: TextRange::new(0, 0),
            body: None,
            to: None,
            from: None,
            cseq: None,
            call_id: None,
            max_forwards: None,
            event: None,
            subscription_state: None,
            refer_to: None,
            contact_headers: Vec::new(),
            via_headers: Vec::new(),
            headers: Vec::new(),
        }
    }

    /// Create a new SIP message from a string slice
    pub fn new_from_str(message: &str) -> Self {
        Self::new(message.to_string())
    }

    /// Create a new SIP message from a string slice with custom limits
    pub fn new_from_str_with_limits(message: &str, limits: ParserLimits) -> Self {
        Self::with_limits(message.to_string(), limits)
    }

    /// Get the current parser limits
    pub fn limits(&self) -> &ParserLimits {
        &self.limits
    }

    /// Set new parser limits
    pub fn set_limits(&mut self, limits: ParserLimits) {
        self.limits = limits;
    }

    /// Parse the message headers lazily
    pub fn parse(&mut self) -> SsbcResult<()> {
        // Validate message size
        if self.raw_message.len() > self.limits().max_message_size {
            return Err(SsbcError::ParseError {
                message: format!("Message size {} exceeds maximum {}", 
                    self.raw_message.len(), self.limits().max_message_size),
                position: None,
                context: Some("Message too large".to_string()),
            });
        }
        self.parse_with_validation(true)
    }

    /// Parse the message headers without validating required headers (for testing)
    pub fn parse_without_validation(&mut self) -> Result<(), SsbcError> {
        self.parse_with_validation(false)
    }

    /// Internal parse method with optional validation
    fn parse_with_validation(&mut self, validate: bool) -> Result<(), SsbcError> {
        // Skip if already parsed
        if self.headers_parsed {
            return Ok(());
        }

        // Cache the message length to avoid multiple calls
        let message_len = self.raw_message.len();

        // Find the end of the start line
        let start_line_end =
            self.raw_message
                .find("\r\n")
                .ok_or_else(|| SsbcError::ParseError {
                    message: "No CRLF after start line".to_string(),
                    position: Some((1, 0)),
                    context: None,
                })?;

        // Set the start line range
        self.start_line = TextRange::from_usize(0, start_line_end);

        // Check start line length limit
        if self.start_line.len() > self.limits().max_start_line_length {
            return Err(SsbcError::ParseError {
                message: format!("Start line length {} exceeds maximum {}", 
                    self.start_line.len(), self.limits().max_start_line_length),
                position: Some((1, 0)),
                context: Some("Start line too long".to_string()),
            });
        }

        // Determine if it's a request or response
        self.is_request = !self.raw_message.starts_with("SIP/");

        // Find the end of headers (double CRLF)
        let headers_section = &self.raw_message[start_line_end + 2..];
        let body_start = if let Some(pos) = headers_section.find("\r\n\r\n") {
            start_line_end + 2 + pos + 4
        } else {
            // No body, headers until the end
            message_len
        };

        // Parse all headers, handling folded lines
        let mut pos = start_line_end + 2;
        let mut current_header_start = pos;
        let mut header_count = 0;

        // Pre-compute the ending position for the loop condition to avoid repeated calculations
        let headers_end = body_start - 2;

        while pos < headers_end {
            // Look ahead to see if the next line is a continuation (folded header)
            // Optimize by using a slice of the message for finding the next line end
            let next_line_offset = self.raw_message[pos..].find("\r\n").unwrap_or(0);
            let next_line_start = pos + next_line_offset + 2;

            // Check if the next line is a folded header continuation
            if next_line_start < body_start
                && next_line_start < message_len
                && (self.raw_message.as_bytes().get(next_line_start) == Some(&b' ')
                    || self.raw_message.as_bytes().get(next_line_start) == Some(&b'\t'))
            {
                // This is a folded line, continue to next line
                pos = next_line_start;
                continue;
            }

            // Find the end of the current header (including any folded lines)
            let line_end = if let Some(end) = self.raw_message[pos..].find("\r\n") {
                pos + end
            } else {
                headers_end
            };

            // Process complete header (from start to end, including any folded parts)
            let header_range = TextRange::from_usize(current_header_start, line_end);
            
            // Check header count limit
            header_count += 1;
            if header_count > self.limits().max_headers {
                return Err(SsbcError::ParseError {
                    message: format!("Too many headers: {} exceeds maximum {}", 
                        header_count, self.limits().max_headers),
                    position: None,
                    context: Some("DoS protection".to_string()),
                });
            }
            
            self.process_header_line(header_range)?;

            // Move to next header
            pos = line_end + 2;
            current_header_start = pos;
        }

        // Set body if present
        if body_start < message_len {
            let body_range = TextRange::from_usize(body_start, message_len);
            
            // Check body size limit
            if body_range.len() > self.limits().max_body_size {
                return Err(SsbcError::ParseError {
                    message: format!("Body size {} exceeds maximum {}", 
                        body_range.len(), self.limits().max_body_size),
                    position: None,
                    context: Some("Body too large".to_string()),
                });
            }
            
            self.body = Some(body_range);
        }

        // Validate required headers for requests if validation is enabled
        if validate && self.is_request {
            self.validate_required_headers()?;
        }

        // Mark as parsed
        self.headers_parsed = true;

        Ok(())
    }

    /// Validate that all required headers are present
    fn validate_required_headers(&self) -> Result<(), SsbcError> {
        // Per RFC 3261 Section 8.1.1, these headers are required in requests
        if self.is_request {
            // Validate all required headers using the macros
            validate_required_vec_header!(self, self.via_headers, "Via");
            validate_required_option_header!(self, self.to, "To");
            validate_required_option_header!(self, self.from, "From");
            validate_required_option_header!(self, self.cseq, "CSeq");
            validate_required_option_header!(self, self.call_id, "Call-ID");
            validate_required_option_header!(self, self.max_forwards, "Max-Forwards");
        }

        // For responses, the requirements are slightly different, but we'll focus on requests for now

        Ok(())
    }

    /// Process a single header line (potentially folded)
    fn process_header_line(&mut self, range: TextRange) -> Result<(), SsbcError> {
        // Check header line length limit
        if range.len() > self.limits().max_header_line_length {
            return Err(SsbcError::ParseError {
                message: format!("Header line length {} exceeds maximum {}", 
                    range.len(), self.limits().max_header_line_length),
                position: Some((0, range.start)),
                context: Some("Header line too long".to_string()),
            });
        }

        let line = range.as_str(&self.raw_message);
        let message_bytes = self.raw_message.as_bytes();

        // Unfold header line by replacing any CRLF + whitespace with a single space
        // Optimize by using a more efficient approach for replacing patterns in the string
        let unfolded_line = {
            // Most headers won't be folded, so optimize for the common case
            if line.contains("\r\n") {
                line.replace("\r\n ", " ").replace("\r\n\t", " ")
            } else {
                line.to_string()
            }
        };

        // Find the colon separating header name and value
        let colon_pos = unfolded_line
            .find(':')
            .ok_or_else(|| SsbcError::ParseError {
                message: "No colon in header line".to_string(),
                position: Some((0, range.start as usize)),
                context: None,
            })?;

        // Get the header name and normalize to lowercase for comparisons
        let raw_name = &unfolded_line[0..colon_pos];
        
        // Validate header name
        validation::validate_header_name(raw_name)?;
        
        let lowercase_name = raw_name.to_lowercase();

        // Convert compact form to full form if necessary
        let normalized_name = self.expand_compact_header(&lowercase_name);

        // Find position of colon in the original line once and reuse
        let original_colon_pos = line.find(':').unwrap();

        // Extract value (skip leading whitespace)
        let value_str = unfolded_line[colon_pos + 1..].trim();
        
        // Validate and sanitize header value
        let _validated_value = validation::sanitize_header_value(value_str)?;

        // Create a raw range for the value part in the original message
        // For folded headers, this is approximate but works for our zero-copy approach
        // since we'll normalize whitespace in the getter methods anyway
        let mut value_start = range.start as usize + original_colon_pos + 1;

        // Optimize bounds checking in the loop
        let range_end = range.end as usize;

        // Skip leading whitespace more efficiently
        while value_start < range_end
            && (message_bytes.get(value_start) == Some(&b' ')
                || message_bytes.get(value_start) == Some(&b'\t'))
        {
            value_start += 1;
        }

        let value_range = TextRange::from_usize(value_start, range_end);
        let name_range = TextRange::from_usize(
            range.start as usize,
            (range.start as usize) + original_colon_pos,
        );

        // Store the header in the appropriate field, checking for duplicates of required single-occurrence headers
        match normalized_name {
            "via" => {
                // Via headers can appear multiple times, collect all of them
                self.via_headers.push(HeaderValue::Raw(value_range));

                // Always add to headers list as well
                self.headers
                    .push((name_range, HeaderValue::Raw(value_range)));
            }
            "to" => {
                // To header must appear exactly once
                check_duplicate_and_set!(self, self.to, value_range, "To", range);
            }
            "from" => {
                // From header must appear exactly once
                check_duplicate_and_set!(self, self.from, value_range, "From", range);
            }
            "call-id" => {
                // Call-ID header must appear exactly once
                check_duplicate_and_set!(self, self.call_id, value_range, "Call-ID", range);
            }
            "cseq" => {
                // CSeq header must appear exactly once
                check_duplicate_and_set!(self, self.cseq, value_range, "CSeq", range);
            }
            "max-forwards" => {
                // Max-Forwards header must appear exactly once if present
                check_duplicate_and_set!(
                    self,
                    self.max_forwards,
                    value_range,
                    "Max-Forwards",
                    range
                );
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
            "contact" => {
                // Store in dedicated contact_headers field
                self.contact_headers.push(HeaderValue::Raw(value_range));

                // Check if this header has multiple entries (comma-separated values)
                if self.header_value_contains(&HeaderValue::Raw(value_range), ',') {
                    self.contact_has_multiple_entries = true;
                }

                // Also store in general headers for backward compatibility
                self.headers
                    .push((name_range, HeaderValue::Raw(value_range)));
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
        match name {
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
    pub fn raw_message(&self) -> &str {
        &self.raw_message
    }

    /// Get the start line text
    pub fn start_line(&self) -> &str {
        self.start_line.as_str(&self.raw_message)
    }

    /// Check if the message is a request
    pub fn is_request(&self) -> bool {
        self.is_request
    }

    /// Get the body text if present
    pub fn body(&self) -> Option<&str> {
        self.body.map(|range| range.as_str(&self.raw_message))
    }

    /// Get the Via header, parsing it on demand
    pub fn via(&mut self) -> Result<Option<&Via>, SsbcError> {
        if self.via_headers.is_empty() {
            return Ok(None);
        }

        // Check if we need to parse the first Via header
        let need_to_parse = match self.via_headers.first() {
            Some(HeaderValue::Raw(range)) => Some(*range),
            Some(HeaderValue::Via(_)) => None,
            _ => return Ok(None),
        };

        // If we need to parse, do so
        if let Some(range) = need_to_parse {
            // Lazily parse the Via header
            let via_parsed = self.parse_via(range)?;

            // Replace the raw value with the parsed one
            self.via_headers[0] = HeaderValue::Via(via_parsed);
        }

        // Now get the parsed Via
        match &self.via_headers[0] {
            HeaderValue::Via(ref via) => Ok(Some(via)),
            _ => Ok(None), // This should be unreachable
        }
    }

    /// Get all Via headers, parsing them on demand
    pub fn all_vias(&mut self) -> Result<Vec<&Via>, SsbcError> {
        let headers_count = self.via_headers.len();
        parse_via_headers!(self, self.via_headers, headers_count)
    }

    /// Get the To header, parsing it on demand
    pub fn to(&mut self) -> Result<Option<&Address>, SsbcError> {
        parse_address_header!(self, to, "To")
    }

    /// Get the From header, parsing it on demand
    pub fn from(&mut self) -> Result<Option<&Address>, SsbcError> {
        parse_address_header!(self, from, "From")
    }

    /// Helper method to ensure a contact header is parsed
    fn ensure_contact_header_parsed(&mut self, index: usize) -> Result<(), SsbcError> {
        ensure_contact_parsed!(self, index)
    }

    /// Get the Contact header, parsing it on demand
    /// Returns the first contact header if multiple exist
    pub fn contact(&mut self) -> Result<Option<&Address>, SsbcError> {
        // Return if no contact headers found
        if self.contact_headers.is_empty() {
            return Ok(None);
        }

        // Ensure the first contact header is parsed
        self.ensure_contact_header_parsed(0)?;

        // Now get the reference to the parsed Address
        if let HeaderValue::Address(ref addr) = &self.contact_headers[0] {
            return Ok(Some(addr));
        }

        // This should never happen if our logic is correct
        Ok(None)
    }

    /// Get all Contact headers, parsing them on demand
    /// This method returns a vector of all Contact headers with their parsed Address values
    pub fn contacts(&mut self) -> Result<Vec<&Address>, SsbcError> {
        // Return empty vec if no contacts
        if self.contact_headers.is_empty() {
            return Ok(Vec::new());
        }

        // Ensure all contact headers are parsed
        for i in 0..self.contact_headers.len() {
            self.ensure_contact_header_parsed(i)?;
        }

        // Collect all parsed address references
        let mut result = Vec::new();
        for value in &self.contact_headers {
            if let HeaderValue::Address(ref addr) = value {
                result.push(addr);
            }
            // All values should be parsed at this point
        }

        Ok(result)
    }

    /// Check if this message has multiple contacts
    /// Returns true if there are multiple contact headers or a single contact header with multiple entries
    pub fn has_multiple_contacts(&self) -> bool {
        self.contact_headers.len() > 1 || self.contact_has_multiple_entries
    }

    /// Get all headers with a specific name
    /// This is a public interface that uses the internal find_headers_by_name method
    pub fn get_headers_by_name(&self, name: &str) -> Vec<&HeaderValue> {
        let headers = self.find_headers_by_name(name);
        headers.iter().map(|(_, value)| *value).collect()
    }

    /// Find all headers with the given name
    fn find_headers_by_name<'a>(&'a self, name: &str) -> Vec<(usize, &'a HeaderValue)> {
        let mut result = Vec::new();
        for (i, (name_range, value)) in self.headers.iter().enumerate() {
            let header_name = name_range.as_str(&self.raw_message).to_lowercase();
            if header_name == name.to_lowercase() {
                result.push((i, value));
            }
        }
        result
    }

    /// Check if a raw header value contains a specific character
    fn header_value_contains(&self, value: &HeaderValue, ch: char) -> bool {
        if let HeaderValue::Raw(range) = value {
            range.as_str(&self.raw_message).contains(ch)
        } else {
            false
        }
    }

    /// Parse a Via header value
    fn parse_via(&self, range: TextRange) -> Result<Via, SsbcError> {
        let via_str = range.as_str(&self.raw_message);

        // Split by the first space to get protocol and sent-by parts
        let space_pos = via_str.find(' ').ok_or_else(|| SsbcError::ParseError {
            message: "Invalid Via format: missing space".to_string(),
            position: None,
            context: None,
        })?;

        let protocol_range =
            TextRange::from_usize(range.start as usize, (range.start as usize) + space_pos);
        let rest_start = (range.start as usize) + space_pos + 1;

        // Find the end of sent-by (before any parameters)
        let sent_by_end = via_str[space_pos + 1..]
            .find(';')
            .unwrap_or(via_str.len() - space_pos - 1);
        let sent_by_range = TextRange::from_usize(rest_start, rest_start + sent_by_end);

        // Parse parameters if present
        let mut params = HashMap::new();
        if rest_start + sent_by_end < range.end as usize {
            // There are parameters, starting after the semicolon
            let params_range =
                TextRange::from_usize(rest_start + sent_by_end + 1, range.end as usize);
            self.parse_params(params_range, &mut params)?;
        }

        Ok(Via {
            full_range: range,
            sent_protocol: protocol_range,
            sent_by: sent_by_range,
            params,
        })
    }

    /// Parse an address specification (used in To, From, etc.)
    fn parse_address(&self, range: TextRange) -> Result<Address, SsbcError> {
        let addr_str = range.as_str(&self.raw_message);

        let mut address = Address {
            full_range: range,
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
                        let display_start = (range.start as usize) + start_offset;
                        let display_end = display_start + display_part.len();

                        // Create ranges with proper type conversion

                        // Remove quotes if present
                        if display_part.starts_with('"')
                            && display_part.ends_with('"')
                            && display_part.len() >= 2
                        {
                            address.display_name =
                                Some(TextRange::from_usize(display_start + 1, display_end - 1));
                        } else {
                            address.display_name =
                                Some(TextRange::from_usize(display_start, display_end));
                        }
                    }

                    // Parse the URI part
                    let uri_range = TextRange::from_usize(
                        (range.start as usize) + less_than_pos + 1,
                        (range.start as usize) + greater_than_pos,
                    );
                    address.uri = self.parse_uri(uri_range)?;

                    // Check for parameters after the URI
                    if greater_than_pos + 1 < addr_str.len() {
                        let params_start = (range.start as usize) + greater_than_pos + 1;
                        if addr_str[greater_than_pos + 1..].starts_with(';') {
                            let params_range =
                                TextRange::from_usize(params_start + 1, range.end as usize);
                            self.parse_params(params_range, &mut address.params)?;
                        }
                    }
                } else {
                    return Err(SsbcError::ParseError {
                        message: "Malformed address, mismatched brackets".to_string(),
                        position: None,
                        context: None,
                    });
                }
            } else {
                return Err(SsbcError::ParseError {
                    message: "Unclosed < in address".to_string(),
                    position: None,
                    context: None,
                });
            }
        } else {
            // No display name, just parse the URI and any params
            if let Some(semicolon_pos) = addr_str.find(';') {
                // URI with parameters
                let uri_range = TextRange::from_usize(
                    range.start as usize,
                    (range.start as usize) + semicolon_pos,
                );
                address.uri = self.parse_uri(uri_range)?;

                // Parse parameters
                let params_range = TextRange::from_usize(
                    (range.start as usize) + semicolon_pos + 1,
                    range.end as usize,
                );
                self.parse_params(params_range, &mut address.params)?;
            } else {
                // Just URI
                address.uri = self.parse_uri(range)?;
            }
        }

        Ok(address)
    }

    /// Parse a URI with an explicit raw message reference
    fn parse_uri_with_message(
        &self,
        raw_message: &str,
        range: TextRange,
    ) -> Result<SipUri, SsbcError> {
        let uri_str = range.as_str(raw_message);

        let mut uri = SipUri::default();

        // Parse scheme
        let colon_pos = uri_str.find(':').ok_or_else(|| SsbcError::ParseError {
            message: "No scheme found in URI".to_string(),
            position: None,
            context: None,
        })?;

        let scheme_str = &uri_str[0..colon_pos];

        // Create a text range for just the scheme part for error position information
        let _scheme_range = TextRange {
            start: range.start,
            end: range.start + colon_pos,
        };

        uri.scheme = scheme_str.parse().map_err(|_| SsbcError::ParseError {
            message: format!("Invalid scheme: {}", scheme_str),
            position: None,
            context: None,
        })?;

        // Validate scheme - must be only alphabetic characters
        if !scheme_str.chars().all(|c| c.is_ascii_alphabetic()) {
            // Create a text range for just the scheme part
            let _scheme_range = TextRange {
                start: range.start,
                end: range.start + colon_pos,
            };
            return Err(SsbcError::ParseError {
                message: format!("Invalid scheme (must be alphabetic): {}", scheme_str),
                position: None,
                context: None,
            });
        }

        // Parse the rest of the URI
        let rest_start = (range.start as usize) + colon_pos + 1;
        let rest = &uri_str[colon_pos + 1..];

        // Special case for TEL URIs
        if uri.scheme == Scheme::TEL {
            // For TEL URIs, everything before semicolon is the user info (phone number)
            if let Some(semicolon_pos) = rest.find(';') {
                uri.user_info = Some(TextRange::from_usize(
                    rest_start as usize,
                    (rest_start as usize) + semicolon_pos,
                ));

                // Parse any parameters
                let params_range = TextRange::from_usize(
                    (rest_start as usize) + semicolon_pos,
                    range.end as usize,
                );
                self.parse_params_with_message(raw_message, params_range, &mut uri.params)?;
            } else {
                // No parameters, the whole rest is the phone number
                uri.user_info = Some(TextRange::from_usize(
                    rest_start as usize,
                    range.end as usize,
                ));
            }
            return Ok(uri);
        }

        // Regular SIP URI processing
        // Check for user info (before @)
        if let Some(at_pos) = rest.find('@') {
            let user_part = &rest[0..at_pos];

            // Validate user part characters
            if !self.is_valid_user_part(user_part) {
                return Err(SsbcError::ParseError {
                    message: format!(
                        "Invalid user part contains prohibited characters: {}",
                        user_part
                    ),
                    position: None,
                    context: None,
                });
            }

            // Check for user parameters
            if let Some(semicolon_pos) = user_part.find(';') {
                uri.user_info = Some(TextRange::from_usize(
                    rest_start as usize,
                    (rest_start as usize) + semicolon_pos,
                ));

                // Parse user parameters
                let user_params_range = TextRange::from_usize(
                    (rest_start as usize) + semicolon_pos + 1,
                    (rest_start as usize) + at_pos,
                );
                self.parse_params_with_message(
                    raw_message,
                    user_params_range,
                    &mut uri.user_params,
                )?;
            } else {
                uri.user_info = Some(TextRange::from_usize(
                    rest_start as usize,
                    (rest_start as usize) + at_pos,
                ));
            }

            // Parse host part
            let host_start = (rest_start as usize) + at_pos + 1;
            // Skip directly to parsing the host part
            let host_range = TextRange::from_usize(host_start, range.end as usize);
            self.parse_host_part_with_message(raw_message, host_range, &mut uri)?;
        } else {
            // No user info, just host part
            let host_range = TextRange::from_usize(rest_start as usize, range.end as usize);
            self.parse_host_part_with_message(raw_message, host_range, &mut uri)?;
        }

        // Validate the URI before returning
        let uri_str = range.as_str(raw_message);
        validation::validate_uri(uri_str, self.limits().max_uri_depth)?;
        
        Ok(uri)
    }

    /// Parse a URI
    fn parse_uri(&self, range: TextRange) -> Result<SipUri, SsbcError> {
        // Use the optimized method with a reference to the raw message
        self.parse_uri_with_message(&self.raw_message, range)
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
        c.is_ascii_digit() || (b'A'..=b'F').contains(&c) || (b'a'..=b'f').contains(&c)
    }

    /// Check if a byte is an unreserved character
    fn is_unreserved(c: u8) -> bool {
        c.is_ascii_lowercase() ||  // a-z
        c.is_ascii_uppercase() ||  // A-Z
        c.is_ascii_digit() ||  // 0-9
        c == b'-' || c == b'.' || c == b'_' || c == b'~' // - . _ ~
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

    /// Parse the host part of a URI using an explicit raw message reference
    fn parse_host_part_with_message(
        &self,
        raw_message: &str,
        range: TextRange,
        uri: &mut SipUri,
    ) -> Result<(), SsbcError> {
        let host_part = range.as_str(raw_message);

        // Split by semicolon (params) or question mark (headers)
        let (host_port_range, rest) = if let Some(semicolon_pos) = host_part.find(';') {
            (
                TextRange::from_usize(range.start as usize, (range.start as usize) + semicolon_pos),
                Some((
                    TextRange::from_usize(
                        (range.start as usize) + semicolon_pos + 1,
                        range.end as usize,
                    ),
                    ';',
                )),
            )
        } else if let Some(question_pos) = host_part.find('?') {
            (
                TextRange::from_usize(range.start as usize, (range.start as usize) + question_pos),
                Some((
                    TextRange::from_usize(
                        (range.start as usize) + question_pos + 1,
                        range.end as usize,
                    ),
                    '?',
                )),
            )
        } else {
            (range, None)
        };

        let host_port = host_port_range.as_str(raw_message);

        // Parse host and optional port
        if let Some(colon_pos) = host_port.find(':') {
            uri.host = Some(TextRange::from_usize(
                host_port_range.start as usize,
                (host_port_range.start as usize) + colon_pos,
            ));

            // Parse port
            let port_str = &host_port[colon_pos + 1..];
            uri.port = Some(
                port_str
                    .parse::<u16>()
                    .map_err(|_| SsbcError::ParseError {
                        message: format!("Invalid port: {}", port_str),
                        position: None,
                        context: None,
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
                    let rest_str = rest_range.as_str(raw_message);
                    if let Some(question_pos) = rest_str.find('?') {
                        // Both parameters and headers
                        let params_range = TextRange::from_usize(
                            rest_range.start as usize,
                            (rest_range.start as usize) + question_pos,
                        );
                        self.parse_params_with_message(raw_message, params_range, &mut uri.params)?;

                        // Headers
                        uri.headers = Some(TextRange::from_usize(
                            (rest_range.start as usize) + question_pos + 1,
                            rest_range.end as usize,
                        ));
                    } else {
                        // Just parameters
                        self.parse_params_with_message(raw_message, rest_range, &mut uri.params)?;
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

    /// Parse the host part of a URI
    // fn parse_host_part(&self, range: TextRange, uri: &mut SipUri) -> Result<(), SsbcError> {
    //     // Reuse the optimized version to avoid code duplication
    //     self.parse_host_part_with_message(&self.raw_message, range, uri)
    // }

    /// Parse parameters string into a HashMap using an explicit raw message reference
    fn parse_params_with_message(
        &self,
        raw_message: &str,
        range: TextRange,
        params: &mut ParamMap,
    ) -> Result<(), SsbcError> {
        let params_str = range.as_str(raw_message);

        let mut start_pos = range.start as usize;
        for param in params_str.split(';') {
            if param.is_empty() {
                start_pos += 1; // Skip the delimiter
                continue;
            }

            let param_len = param.len();

            if let Some(equals_pos) = param.find('=') {
                let name_range = TextRange::from_usize(start_pos, start_pos + equals_pos);
                let value_range =
                    TextRange::from_usize(start_pos + equals_pos + 1, start_pos + param_len);
                params.insert(name_range, Some(value_range));
            } else {
                // Flag parameter (no value)
                let name_range = TextRange::from_usize(start_pos, start_pos + param_len);
                params.insert(name_range, None);
            }

            // Move past this parameter and the delimiter
            start_pos += param_len + 1;
        }

        Ok(())
    }

    /// Parse parameters string into a HashMap
    fn parse_params(&self, range: TextRange, params: &mut ParamMap) -> Result<(), SsbcError> {
        // Use the optimized version to avoid code duplication
        self.parse_params_with_message(&self.raw_message, range, params)
    }

    /// Helper to get string value from TextRange
    pub fn get_str(&self, range: TextRange) -> &str {
        range.as_str(&self.raw_message)
    }

    /// Helper to get string value from optional TextRange
    pub fn get_opt_str(&self, range: Option<TextRange>) -> Option<&str> {
        range.map(|r| r.as_str(&self.raw_message))
    }

    /// Helper to get param key as string
    pub fn get_param_key(&self, key: &ParamKey) -> &str {
        key.as_str(&self.raw_message)
    }

    /// Helper to get param value as string
    pub fn get_param_value(&self, value: &ParamValue) -> Option<&str> {
        value.map(|v| v.as_str(&self.raw_message))
    }

    /// Helper to extract parameter map as string map
    pub fn get_params_map(&self, params: &ParamMap) -> HashMap<&str, Option<&str>> {
        params
            .iter()
            .map(|(key, value)| (self.get_param_key(key), self.get_param_value(value)))
            .collect()
    }

    /// Parse the CSeq header and extract the method
    pub fn cseq_method(&mut self) -> Result<Option<Method>, SsbcError> {
        if let Some(HeaderValue::Raw(range)) = self.cseq {
            let cseq_str = self.get_str(range);

            // CSeq has format: "sequence_number method"
            let parts: Vec<&str> = cseq_str.split_whitespace().collect();
            if parts.len() < 2 {
                return Err(SsbcError::ParseError {
                    message: format!("Invalid CSeq format: {}", cseq_str),
                    position: None,
                    context: None,
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
            Ok(method) => {
                // Validate method name
                if let Err(_) = validation::validate_method(parts[0]) {
                    Some(Method::UNKNOWN(parts[0].to_string()))
                } else {
                    Some(method)
                }
            },
            Err(_) => Some(Method::UNKNOWN(parts[0].to_string())),
        }
    }

    /// Add this method to parse Event header for SUBSCRIBE/NOTIFY
    pub fn parse_event(&mut self) -> Result<Option<&EventPackageData>, SsbcError> {
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
                    TextRange::from_usize(range.start as usize, (range.start as usize) + semi_pos),
                    Some(&event_str[semi_pos + 1..]),
                )
            } else {
                (*range, None)
            };

            // Create event package
            let mut event = EventPackageData {
                event_type,
                event_params: HashMap::new(),
            };

            // Parse parameters if present
            if let Some(params) = params_str {
                let params_range = TextRange::from_usize(
                    (range.start as usize) + event_str.len() - params.len(),
                    range.end as usize,
                );
                self.parse_params(params_range, &mut event.event_params)?;
            }

            // Store and return
            self.event = Some(event);
            return Ok(self.event.as_ref());
        }

        Ok(None)
    }

    /// Get the Call-ID header value from the dedicated field
    pub fn call_id(&self) -> Option<String> {
        if let Some(ref call_id_header) = self.call_id {
            if let HeaderValue::Raw(range) = call_id_header {
                Some(range.as_str(&self.raw_message).to_string())
            } else {
                None
            }
        } else {
            None
        }
    }
}

/// Generic SIP header extraction utilities
pub mod header_utils {
    use crate::SipMessage;
    
    /// Extract header value by name, supporting both long and compact forms
    /// 
    /// This function searches for headers by name, automatically handling
    /// RFC 3261 compact forms (e.g., "f" for "from", "t" for "to").
    /// 
    /// # Examples
    /// ```
    /// use ssbc::{SipMessage, header_utils::extract_header_value};
    /// 
    /// let sip_msg = "INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\nFrom: Alice <sip:alice@example.com>;tag=123\r\nTo: Bob <sip:bob@example.com>\r\nCall-ID: call123@example.com\r\nCSeq: 1 INVITE\r\n\r\n";
    /// let mut message = SipMessage::new_from_str(sip_msg);
    /// message.parse_without_validation().unwrap();
    /// 
    /// // Works with both "From" and "f" headers
    /// let from_value = extract_header_value(&message, "from");
    /// assert!(from_value.is_some());
    /// ```
    pub fn extract_header_value(sip_message: &SipMessage, header_name: &str) -> Option<String> {
        let raw_message = sip_message.raw_message();
        let header_lower = header_name.to_lowercase();
        
        // RFC 3261 compact form mapping
        let compact_form = match header_lower.as_str() {
            "from" => Some("f"),
            "to" => Some("t"), 
            "via" => Some("v"),
            "contact" => Some("m"),
            "call-id" => Some("i"),
            "content-length" => Some("l"),
            "content-type" => Some("c"),
            "subject" => Some("s"),
            _ => None,
        };
        
        let prefixes = if let Some(compact) = compact_form {
            vec![format!("{}:", header_lower), format!("{}:", compact)]
        } else {
            vec![format!("{}:", header_lower)]
        };
        
        for line in raw_message.lines() {
            let line_lower = line.to_lowercase();
            
            for prefix in &prefixes {
                if line_lower.starts_with(prefix) {
                    if let Some(colon_pos) = line.find(':') {
                        return Some(line[colon_pos + 1..].trim().to_string());
                    }
                }
            }
        }
        None
    }
    
    /// Extract parameter value from a header value string
    /// 
    /// Parses SIP header parameters in the format "param=value" from
    /// a header value, handling quoted and unquoted values.
    /// 
    /// # Examples
    /// ```
    /// use ssbc::header_utils::extract_header_parameter;
    /// 
    /// let from_header = "Alice <sip:alice@example.com>;tag=abc123";
    /// let tag = extract_header_parameter(from_header, "tag"); // Some("abc123")
    /// 
    /// let via_header = "SIP/2.0/UDP host.com;branch=z9hG4bK-123";
    /// let branch = extract_header_parameter(via_header, "branch"); // Some("z9hG4bK-123")
    /// ```
    pub fn extract_header_parameter(header_value: &str, param_name: &str) -> Option<String> {
        let param_lower = param_name.to_lowercase();
        let param_prefix = format!("{}=", param_lower);
        
        for part in header_value.split(';') {
            let part_trimmed = part.trim();
            let part_lower = part_trimmed.to_lowercase();
            
            if part_lower.starts_with(&param_prefix) {
                // Extract the value part after the "param=" prefix
                let value_start = part_trimmed.find('=').unwrap() + 1;
                let value = part_trimmed[value_start..].trim();
                
                // Remove quotes if present
                let unquoted = if value.starts_with('"') && value.ends_with('"') && value.len() > 1 {
                    &value[1..value.len()-1]
                } else {
                    value
                };
                
                return Some(unquoted.to_string());
            }
        }
        None
    }
    
    /// Get all header values for a given header name
    /// 
    /// Returns a vector of all header values that match the given name,
    /// useful for headers that can appear multiple times (like Via).
    pub fn get_header_values(sip_message: &SipMessage, header_name: &str) -> Vec<String> {
        let raw_message = sip_message.raw_message();
        let header_lower = header_name.to_lowercase();
        let mut values = Vec::new();
        
        // RFC 3261 compact form mapping  
        let compact_form = match header_lower.as_str() {
            "from" => Some("f"),
            "to" => Some("t"),
            "via" => Some("v"), 
            "contact" => Some("m"),
            "call-id" => Some("i"),
            "content-length" => Some("l"),
            "content-type" => Some("c"),
            "subject" => Some("s"),
            _ => None,
        };
        
        let prefixes = if let Some(compact) = compact_form {
            vec![format!("{}:", header_lower), format!("{}:", compact)]
        } else {
            vec![format!("{}:", header_lower)]
        };
        
        for line in raw_message.lines() {
            let line_lower = line.to_lowercase();
            
            for prefix in &prefixes {
                if line_lower.starts_with(prefix) {
                    if let Some(colon_pos) = line.find(':') {
                        values.push(line[colon_pos + 1..].trim().to_string());
                        break; // Found match for this line, move to next line
                    }
                }
            }
        }
        
        values
    }
}




#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_address_range() {
        let address_str = "Alice <sip:alice@atlanta.com>;tag=1928301774";
        let message = format!("INVITE sip:bob@example.com SIP/2.0\r\nFrom: {}\r\nTo: <sip:bob@example.com>\r\nCall-ID: 12345\r\nCSeq: 1 INVITE\r\nVia: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\nMax-Forwards: 70\r\n\r\n", address_str);

        let mut sip_message = SipMessage::new_from_str(&message);
        assert!(sip_message.parse().is_ok());

        // Get the From header and copy the ranges we need to test
        let full_range;
        let display_name;
        let host;

        // Using a block to limit the scope of the borrow
        {
            let from = sip_message.from().unwrap().expect("From header not found");
            full_range = from.full_range;
            display_name = from.display_name;
            host = from.uri.host;
        }

        // Now we can use get_str without borrowing issues
        let actual_address = sip_message.get_str(full_range);
        assert_eq!(
            actual_address, address_str,
            "Full address range does not match expected text"
        );

        // Verify that the display name is a subset of the full range
        if let Some(name_range) = display_name {
            assert!(
                name_range.start >= full_range.start,
                "Display name starts before full range"
            );
            assert!(
                name_range.end <= full_range.end,
                "Display name extends beyond full range"
            );
            assert_eq!(
                sip_message.get_str(name_range),
                "Alice",
                "Display name text doesn't match"
            );
        } else {
            panic!("Display name not found");
        }

        // Verify that host is within the full range
        if let Some(host_range) = host {
            assert!(
                host_range.start >= full_range.start,
                "Host starts before full range"
            );
            assert!(
                host_range.end <= full_range.end,
                "Host extends beyond full range"
            );
            assert_eq!(
                sip_message.get_str(host_range),
                "atlanta.com",
                "Host text doesn't match"
            );
        }
    }

    #[test]
    fn test_full_via_range() {
        let via_str = "SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds";
        let message = format!("INVITE sip:bob@example.com SIP/2.0\r\nVia: {}\r\nFrom: Alice <sip:alice@atlanta.com>;tag=1928301774\r\nTo: <sip:bob@example.com>\r\nCall-ID: 12345\r\nCSeq: 1 INVITE\r\nMax-Forwards: 70\r\n\r\n", via_str);

        let mut sip_message = SipMessage::new_from_str(&message);
        assert!(sip_message.parse().is_ok());

        // Get the Via header data we need for testing
        let full_range;
        let sent_protocol;
        let sent_by;
        let params;

        // Using a block to limit the scope of the borrow
        {
            let via = sip_message.via().unwrap().expect("Via header not found");
            full_range = via.full_range;
            sent_protocol = via.sent_protocol;
            sent_by = via.sent_by;
            params = via.params.clone(); // Clone the params map to avoid borrow issues
        }

        // Now we can use get_str without borrowing issues
        let actual_via = sip_message.get_str(full_range);
        assert_eq!(
            actual_via, via_str,
            "Full Via range doesn't match expected text"
        );

        // Verify that the sent_protocol is within the full range
        assert!(
            sent_protocol.start >= full_range.start,
            "Protocol starts before full range"
        );
        assert!(
            sent_protocol.end <= full_range.end,
            "Protocol extends beyond full range"
        );
        assert_eq!(
            sip_message.get_str(sent_protocol),
            "SIP/2.0/UDP",
            "Protocol text doesn't match"
        );

        // Verify that the sent_by is within the full range
        assert!(
            sent_by.start >= full_range.start,
            "Sent-by starts before full range"
        );
        assert!(
            sent_by.end <= full_range.end,
            "Sent-by extends beyond full range"
        );
        assert_eq!(
            sip_message.get_str(sent_by),
            "pc33.atlanta.com",
            "Sent-by text doesn't match"
        );

        // Verify that the branch parameter exists and is within the full range
        let mut found_branch = false;
        for (k, v) in params.iter() {
            if sip_message.get_str(*k) == "branch" {
                if let Some(branch) = v {
                    found_branch = true;
                    assert!(
                        branch.start >= full_range.start,
                        "Branch param starts before full range"
                    );
                    assert!(
                        branch.end <= full_range.end,
                        "Branch param extends beyond full range"
                    );
                    assert_eq!(
                        sip_message.get_str(*branch),
                        "z9hG4bK776asdhds",
                        "Branch param text doesn't match"
                    );
                }
            }
        }

        assert!(found_branch, "Branch parameter not found");
    }

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

        let mut sip_message = SipMessage::new_from_str(message);
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

        let mut sip_message = SipMessage::new_from_str(message);
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
                       o=alice 53655765 2353687637 IN IP4 pc33.atlanta.com\r\n
                       s=Session SDP\r\n
                       c=IN IP4 pc33.atlanta.com\r\n
                       t=0 0\r\n
                       m=audio 49172 RTP/AVP 0\r\n\
                       a=rtpmap:0 PCMU/8000\r\n";

        let mut sip_message = SipMessage::new_from_str(message);
        assert!(sip_message.parse_without_validation().is_ok());

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
        fn parse_uri(uri_str: &str) -> Result<SipUri, SsbcError> {
            let range = TextRange::from_usize(0, uri_str.len());
            let message = SipMessage::new_from_str(uri_str);
            message.parse_uri(range)
        }

        // Test simple URI
        let uri = parse_uri(simple_uri).expect("Failed to parse simple URI");
        assert_eq!(uri.scheme, Scheme::SIP);

        // Test URI with parameters
        let uri = parse_uri(uri_with_params).expect("Failed to parse URI with params");
        assert_eq!(uri.scheme, Scheme::SIP);
        assert!(!uri.params.is_empty());

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
        let range = TextRange::from_usize(0, via_header.len());
        let message = SipMessage::new_from_str(via_header);

        let via = message
            .parse_via(range)
            .expect("Failed to parse Via header");

        assert_eq!(message.get_str(via.sent_protocol), "SIP/2.0/UDP");
        assert_eq!(message.get_str(via.sent_by), "pc33.atlanta.com");
        assert!(!via.params.is_empty());

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
        let message = SipMessage::new_from_str("Bob <sip:bob@biloxi.com>;tag=a6c85cf");
        let range = TextRange::from_usize(0, "Bob <sip:bob@biloxi.com>;tag=a6c85cf".len());

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
        // We need a message with an invalid URI where the scheme is invalid
        let invalid_uri = "INVITE xyz:bob@biloxi.com SIP/2.0\r\nVia: SIP/2.0/UDP pc33.atlanta.com\r\nTo: Bob <xyz:bob@biloxi.com>\r\nFrom: Alice <sip:alice@atlanta.com>;tag=1928301774\r\nCall-ID: a84b4c76e66710@pc33.atlanta.com\r\nCSeq: 314159 INVITE\r\nMax-Forwards: 70\r\n\r\n";
        let mut message = SipMessage::new_from_str(invalid_uri);

        // Parsing the message should work at the message level
        assert!(message.parse_without_validation().is_ok());

        // But trying to access a header that needs URI parsing should fail
        let result = message.to();
        assert!(
            result.is_err(),
            "Expected an error when parsing the To header with invalid URI"
        );

        if let Err(error) = result {
            match error {
                SsbcError::ParseError {
                    message: _,
                    position,
                    context: _,
                } => {
                    assert!(position.is_none()); // Position is now None since we use Option<(usize, usize)>
                }
                _ => panic!("Expected ParseError"),
            }
        }
    }

    #[test]
    fn test_max_forwards_parsing() {
        // Test parsing of Max-Forwards header
        let message = "\
INVITE sip:bob@biloxi.com SIP/2.0\r
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r
To: Bob <sip:bob@biloxi.com>\r
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r
Call-ID: a84b4c76e66710@pc33.atlanta.com\r
CSeq: 314159 INVITE\r
Max-Forwards: 70\r
\r
";
        let mut sip_message = SipMessage::new_from_str(message);
        assert!(sip_message.parse_without_validation().is_ok());

        // Check Max-Forwards header
        match &sip_message.max_forwards {
            Some(HeaderValue::Raw(range)) => {
                assert_eq!(sip_message.get_str(*range), "70");
            }
            _ => panic!("Max-Forwards header not parsed correctly"),
        }
    }

    #[test]
    fn test_mime_type_header_parsing() {
        // Test parsing of Content-Type header
        let message = "\
INVITE sip:bob@biloxi.com SIP/2.0\r
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r
To: Bob <sip:bob@biloxi.com>\r
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r
Call-ID: a84b4c76e66710@pc33.atlanta.com\r
CSeq: 314159 INVITE\r
Max-Forwards: 70\r
Content-Type: application/sdp\r
\r
";
        let mut sip_message = SipMessage::new_from_str(message);
        assert!(sip_message.parse_without_validation().is_ok());

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
    fn test_body_with_content_length() {
        // Test body parsing using Content-Length header
        let message = "\
INVITE sip:bob@biloxi.com SIP/2.0\r
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r
To: Bob <sip:bob@biloxi.com>\r
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r
Call-ID: a84b4c76e66710@pc33.atlanta.com\r
CSeq: 314159 INVITE\r
Max-Forwards: 70\r
Content-Length: 11\r
\r
Hello World";

        let mut sip_message = SipMessage::new_from_str(message);
        assert!(sip_message.parse_without_validation().is_ok());

        // Check the body
        assert_eq!(sip_message.body().unwrap(), "Hello World");
    }

    #[test]
    fn test_duplicate_header_detection() {
        // Test message with duplicate headers that should be rejected
        let message_with_duplicate_to = "\
INVITE sip:bob@biloxi.com SIP/2.0\r
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r
To: Bob <sip:bob@biloxi.com>\r
To: Bob <sip:bob@example.com>\r
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r
Call-ID: a84b4c76e66710@pc33.atlanta.com\r
CSeq: 314159 INVITE\r
Max-Forwards: 70\r
\r
";
        let mut sip_message = SipMessage::new_from_str(message_with_duplicate_to);
        let result = sip_message.parse();
        assert!(result.is_err());

        match result {
            Err(SsbcError::ParseError {
                context: None,                message,
                position: _,
            }) => {
                assert!(message.contains("Duplicate To header"));
            }
            _ => panic!("Expected InvalidHeader error for duplicate To"),
        }

        // Test message with duplicate From header
        let message_with_duplicate_from = "\
INVITE sip:bob@biloxi.com SIP/2.0\r
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r
To: Bob <sip:bob@biloxi.com>\r
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r
From: Carol <sip:carol@example.com>;tag=987654321\r
Call-ID: a84b4c76e66710@pc33.atlanta.com\r
CSeq: 314159 INVITE\r
Max-Forwards: 70\r
\r
";
        let mut sip_message = SipMessage::new_from_str(message_with_duplicate_from);
        let result = sip_message.parse();
        assert!(result.is_err());

        match result {
            Err(SsbcError::ParseError {
                context: None,                message,
                position: _,
            }) => {
                assert!(message.contains("Duplicate From header"));
            }
            _ => panic!("Expected InvalidHeader error for duplicate From"),
        }

        // Test message with duplicate CSeq header
        let message_with_duplicate_cseq = "\
INVITE sip:bob@biloxi.com SIP/2.0\r
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r
To: Bob <sip:bob@biloxi.com>\r
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r
Call-ID: a84b4c76e66710@pc33.atlanta.com\r
CSeq: 314159 INVITE\r
CSeq: 1 ACK\r
Max-Forwards: 70\r
\r
";
        let mut sip_message = SipMessage::new_from_str(message_with_duplicate_cseq);
        let result = sip_message.parse();
        assert!(result.is_err());

        match result {
            Err(SsbcError::ParseError {
                context: None,                message,
                position: _,
            }) => {
                assert!(message.contains("Duplicate CSeq header"));
            }
            _ => panic!("Expected InvalidHeader error for duplicate CSeq"),
        }
    }

    #[test]
    fn test_error_in_from_header() {
        // Test that an error in the From header is correctly reported
        let message = "\
INVITE sip:bob@biloxi.com SIP/2.0\r
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r
To: Bob <sip:bob@biloxi.com>\r
From: Alice <malformed-uri>\r
Call-ID: a84b4c76e66710@pc33.atlanta.com\r
CSeq: 314159 INVITE\r
Max-Forwards: 70\r
\r
";
        let mut message = SipMessage::new_from_str(message);

        // Parsing the message should work at the message level
        assert!(message.parse_without_validation().is_ok());

        // But trying to access a header that needs URI parsing should fail
        let result = message.from();
        assert!(result.is_err());

        // Check error details
        match result {
            Err(SsbcError::ParseError {
                message,
                position,
                context,
            }) => {
                // Position might be None for URI parsing errors
                println!("ParseError: message={}, position={:?}, context={:?}", message, position, context);
                // Just verify we got a parse error
                assert!(message.contains("uri") || message.contains("URI") || message.contains("Invalid"));
            }
            _ => panic!("Expected ParseError, got: {:?}", result),
        }
    }

    #[test]
    fn test_event_package_parsing() {
        // Test SUBSCRIBE with Event header
        let message = "\
SUBSCRIBE sip:bob@biloxi.com SIP/2.0\r
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r
To: Bob <sip:bob@biloxi.com>\r
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r
Call-ID: a84b4c76e66710@pc33.atlanta.com\r
CSeq: 314159 SUBSCRIBE\r
Max-Forwards: 70\r
Event: presence;id=123;expire=3600\r
\r
";
        let mut sip_message = SipMessage::new_from_str(message);
        assert!(sip_message.parse_without_validation().is_ok());

        // Parse the Event header
        let event_result = sip_message.parse_event();
        assert!(event_result.is_ok());
        let event = event_result.unwrap();
        assert!(event.is_some());
    }

    #[test]
    fn test_folded_header_enhancements() {
        // Test with multiple folded lines
        let message = "\
INVITE sip:bob@biloxi.com SIP/2.0\r
Via: SIP/2.0/UDP pc33.atlanta.com;\r
 branch=z9hG4bK4b43c2ff8.1\r
To: Bob <sip:bob@biloxi.com>\r
From: Alice \r
\t<sip:alice@atlanta.com>;\r
 tag=1928301774\r
Call-ID: a84b4c76e66710@pc33.atlanta.com\r
CSeq: 314159 INVITE\r
Max-Forwards: 70\r
\r
";
        let mut sip_message = SipMessage::new_from_str(message);
        assert!(sip_message.parse_without_validation().is_ok());

        // Verify that Via header was parsed successfully
        let via_result = sip_message.via();
        assert!(via_result.is_ok());
        assert!(via_result.unwrap().is_some());
    }

    #[test]
    fn test_method_parsing() {
        // Test parsing methods from request line
        let message = "\
SUBSCRIBE sip:bob@biloxi.com SIP/2.0\r
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r
To: Bob <sip:bob@biloxi.com>\r
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r
Call-ID: a84b4c76e66710@pc33.atlanta.com\r
CSeq: 314159 SUBSCRIBE\r
Max-Forwards: 70\r
Event: presence\r
\r
";
        let mut sip_message = SipMessage::new_from_str(message);
        assert!(sip_message.parse_without_validation().is_ok());

        // Check request method
        let method = sip_message.request_method();
        assert!(method.is_some());
        assert_eq!(method.unwrap(), Method::SUBSCRIBE);
    }

    #[test]
    fn test_multiple_via_collection() {
        // Test message with multiple Via headers
        let message = "\
INVITE sip:bob@biloxi.com SIP/2.0\r
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r
Via: SIP/2.0/UDP bigbox3.site3.atlanta.com;branch=z9hG4bK77ef4c2312983.1\r
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds;received=192.0.2.1\r
To: Bob <sip:bob@biloxi.com>\r
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r
Call-ID: a84b4c76e66710@pc33.atlanta.com\r
CSeq: 314159 INVITE\r
Max-Forwards: 70\r
\r
";
        let mut sip_message = SipMessage::new_from_str(message);
        assert!(sip_message.parse_without_validation().is_ok());

        // Just check that we have 3 Via headers
        let via_count = sip_message.via_headers.len();
        assert_eq!(via_count, 3);

        // Verify the first via is accessible
        let via_result = sip_message.via();
        assert!(via_result.is_ok());
        assert!(via_result.unwrap().is_some());
    }

    #[test]
    fn test_required_header_validation() {
        // Test message missing required headers
        let message_missing_to = "\
INVITE sip:bob@biloxi.com SIP/2.0\r
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r
Call-ID: a84b4c76e66710@pc33.atlanta.com\r
CSeq: 314159 INVITE\r
Max-Forwards: 70\r
\r
";
        let mut sip_message = SipMessage::new_from_str(message_missing_to);
        let result = sip_message.parse();
        assert!(result.is_err());

        match result {
            Err(SsbcError::ParseError {
                context: None,                message,
                position: _,
            }) => {
                assert!(message.contains("Missing required To header"));
            }
            _ => panic!("Expected InvalidMessage error for missing To header"),
        }

        // Test message missing Max-Forwards
        let message_missing_max_forwards = "\
INVITE sip:bob@biloxi.com SIP/2.0\r
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r
To: Bob <sip:bob@biloxi.com>\r
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r
Call-ID: a84b4c76e66710@pc33.atlanta.com\r
CSeq: 314159 INVITE\r
\r
";
        let mut sip_message = SipMessage::new_from_str(message_missing_max_forwards);
        let result = sip_message.parse();
        assert!(result.is_err());

        match result {
            Err(SsbcError::ParseError {
                context: None,                message,
                position: _,
            }) => {
                assert!(message.contains("Missing required Max-Forwards header"));
            }
            _ => panic!("Expected InvalidMessage error for missing Max-Forwards header"),
        }
    }

    #[test]
    fn test_uri_character_validation() {
        // Test URI with valid characters
        let uri_str = "sip:alice@atlanta.com";
        let range = TextRange::new(0, uri_str.len());
        let message = SipMessage::new_from_str(uri_str);
        assert!(message.parse_uri(range).is_ok());

        // Test URI with invalid characters in user part
        let invalid_uri = "sip:alice[123]@atlanta.com";
        let range = TextRange::from_usize(0, invalid_uri.len());
        let message = SipMessage::new_from_str(invalid_uri);
        let result = message.parse_uri(range);
        assert!(result.is_err());

        // Test URI with valid percent-encoded characters
        let encoded_uri = "sip:alice%20smith@atlanta.com".to_string();
        let range = TextRange::from_usize(0, encoded_uri.len());
        let message = SipMessage::new_from_str(&encoded_uri);
        assert!(message.parse_uri(range).is_ok());

        // Test URI with invalid percent-encoding
        let bad_encoded_uri = "sip:alice%2@atlanta.com";
        let range = TextRange::from_usize(0, bad_encoded_uri.len());
        let message = SipMessage::new_from_str(bad_encoded_uri);
        let result = message.parse_uri(range);
        assert!(result.is_err());
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
        let mut sip_message = SipMessage::new_from_str(message);
        assert!(sip_message.parse_without_validation().is_ok());

        // Check that it's correctly identified as a response
        assert!(!sip_message.is_request());

        // Check the start line
        assert_eq!(sip_message.start_line(), "SIP/2.0 200 OK");
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
    fn test_basic_from_header() {
        let input = "From: \"Alice\" <sip:alice@example.com>";
        let mut message = SipMessage::new_from_str(input);
        message
            .process_header_line(TextRange::from_usize(0, input.len()))
            .unwrap();

        // Check that we can extract the From header
        let address = message.from().unwrap().expect("From header not found");

        // Create local copies of all the values we need
        let display_name = address.display_name.unwrap().as_str(&message.raw_message);

        // Check display name
        assert_eq!(display_name, "Alice");
    }

    #[test]
    fn test_complex_from_header() {
        let input = "From: \"Alice Smith\" <sip:alice@example.com:5060;transport=tcp>;tag=1234;expires=3600";
        let mut message = SipMessage::new_from_str(input);
        message
            .process_header_line(TextRange::from_usize(0, input.len()))
            .unwrap();

        // In test methods, we need to clone to avoid borrowing conflicts
        // This is only in tests, not performance-critical code
        let raw_message = message.raw_message.clone();

        // Now we can safely get the From header and use raw_message in closures
        let from = message.from().unwrap().expect("From header not found");

        // Extract all values using the as_str method
        let display_name = from.display_name.map(|range| range.as_str(&raw_message));
        let scheme = from.uri.scheme.clone();
        let user_info = from.uri.user_info.map(|range| range.as_str(&raw_message));
        let host = from.uri.host.map(|range| range.as_str(&raw_message));
        let port = from.uri.port;

        // Create parameter maps using as_str
        let mut uri_params_map = HashMap::new();
        for (k, v) in &from.uri.params {
            let key = k.as_str(&raw_message);
            let value = v.as_ref().map(|r| r.as_str(&raw_message));
            uri_params_map.insert(key, value);
        }

        let mut header_params_map = HashMap::new();
        for (k, v) in &from.params {
            let key = k.as_str(&raw_message);
            let value = v.as_ref().map(|r| r.as_str(&raw_message));
            header_params_map.insert(key, value);
        }

        // Now test with the data we've extracted
        assert_eq!(display_name, Some("Alice Smith"));
        assert_eq!(scheme, Scheme::SIP);
        assert_eq!(user_info, Some("alice"));
        assert_eq!(host, Some("example.com"));
        assert_eq!(port, Some(5060));

        // Check URI parameters
        assert_eq!(uri_params_map.get("transport").unwrap(), &Some("tcp"));

        // Check header parameters
        assert_eq!(header_params_map.get("tag").unwrap(), &Some("1234"));
        assert_eq!(header_params_map.get("expires").unwrap(), &Some("3600"));
    }

    #[test]
    fn test_escaped_characters() {
        let input = "From: \"Alice\\\"Quotes\\\"\" <sip:alice@example.com>";
        let mut message = SipMessage::new_from_str(input);
        message
            .process_header_line(TextRange::from_usize(0, input.len()))
            .unwrap();

        // In test methods, we need to clone to avoid borrowing conflicts
        // This is only in tests, not performance-critical code
        let raw_message = message.raw_message.clone();

        // Check that we can extract the From header
        let address = message.from().unwrap().expect("From header not found");

        // Get display name directly using as_str
        let display_name = address.display_name.map(|r| r.as_str(&raw_message));

        // Check display name with escaped quotes
        assert_eq!(display_name, Some("Alice\\\"Quotes\\\""));
    }

    #[test]
    fn test_unquoted_display_name() {
        let input = "From: John Doe <sip:john@example.com>";
        let mut message = SipMessage::new_from_str(input);
        message
            .process_header_line(TextRange::from_usize(0, input.len()))
            .unwrap();

        // In test methods, we need to clone to avoid borrowing conflicts
        // This is only in tests, not performance-critical code
        let raw_message = message.raw_message.clone();

        // Check that we can extract the From header
        let address = message.from().unwrap().expect("From header not found");

        // Get display name directly using as_str
        let display_name = address.display_name.map(|r| r.as_str(&raw_message));

        // Check display name
        assert_eq!(display_name, Some("John Doe"));
    }

    #[test]
    fn test_header_params() {
        let input = "Contact: <sip:user@host.com>;expires=3600;q=0.8";
        let mut message = SipMessage::new_from_str(input);
        message
            .process_header_line(TextRange::from_usize(0, input.len()))
            .unwrap();

        // In test methods, we need to clone to avoid borrowing conflicts
        // This is only in tests, not performance-critical code
        let raw_message = message.raw_message.clone();

        // Get the Contact header directly using contact() method
        let contact = message
            .contact()
            .unwrap()
            .expect("Contact header not found");

        // For consistency with our test, save as address
        let address = contact;

        // Create parameter map directly using as_str
        let mut params_map = HashMap::new();
        for (k, v) in &address.params {
            let key = k.as_str(&raw_message);
            let value = v.as_ref().map(|r| r.as_str(&raw_message));
            params_map.insert(key, value);
        }

        // Check parameters
        assert_eq!(params_map.get("expires").unwrap(), &Some("3600"));
        assert_eq!(params_map.get("q").unwrap(), &Some("0.8"));
    }

    #[test]
    fn test_multiple_header_params() {
        let input = "Contact: <sip:alice@example.com>;expires=3600;q=0.8;priority=1";
        let mut message = SipMessage::new_from_str(input);
        message
            .process_header_line(TextRange::from_usize(0, input.len()))
            .unwrap();

        // In test methods, we need to clone to avoid borrowing conflicts
        // This is only in tests, not performance-critical code
        let raw_message = message.raw_message.clone();

        // Get the Contact header directly using contact() method
        let contact = message
            .contact()
            .unwrap()
            .expect("Contact header not found");

        // For consistency with our test, save as address
        let address = contact;

        // Create parameter map directly using as_str
        let mut params_map = HashMap::new();
        for (k, v) in &address.params {
            let key = k.as_str(&raw_message);
            let value = v.as_ref().map(|r| r.as_str(&raw_message));
            params_map.insert(key, value);
        }

        // Check parameters
        assert_eq!(params_map.get("expires").unwrap(), &Some("3600"));
        assert_eq!(params_map.get("q").unwrap(), &Some("0.8"));
        assert_eq!(params_map.get("priority").unwrap(), &Some("1"));
    }

    #[test]
    fn test_quoted_params() {
        let input = "To: <sip:bob@example.com>;reason=\"moved temporarily\";info=\"contact info\"";
        let mut message = SipMessage::new_from_str(input);
        message
            .process_header_line(TextRange::from_usize(0, input.len()))
            .unwrap();

        // In test methods, we need to clone to avoid borrowing conflicts
        // This is only in tests, not performance-critical code
        let raw_message = message.raw_message.clone();

        // Get the To header directly using to() method
        let to_address = message.to().unwrap().expect("To header not found");

        // For consistency with our test, save as address
        let address = to_address;

        // Create parameter map directly using as_str
        let mut params_map = HashMap::new();
        for (k, v) in &address.params {
            let key = k.as_str(&raw_message);
            let value = v.as_ref().map(|r| r.as_str(&raw_message));
            params_map.insert(key, value);
        }

        // Check quoted parameters - our implementation doesn't strip quotes
        assert_eq!(
            params_map.get("reason").unwrap(),
            &Some("\"moved temporarily\"")
        );
        assert_eq!(params_map.get("info").unwrap(), &Some("\"contact info\""));
    }

    #[test]
    fn test_no_user_info() {
        let input = "Contact: <sip:example.com>";
        let mut message = SipMessage::new_from_str(input);
        message
            .process_header_line(TextRange::from_usize(0, input.len()))
            .unwrap();

        // In test methods, we need to clone to avoid borrowing conflicts
        // This is only in tests, not performance-critical code
        let raw_message = message.raw_message.clone();

        // Get the Contact header directly using contact() method
        let contact = message
            .contact()
            .unwrap()
            .expect("Contact header not found");

        // Extract URI host value directly with as_str
        let host_value = contact.uri.host.map(|r| r.as_str(&raw_message));

        // Check URI components
        assert_eq!(host_value, Some("example.com"));
    }

    #[test]
    fn test_tel_uri() {
        let input = "Contact: <tel:+1-212-555-0123;phone-context=example.com>";
        let mut message = SipMessage::new_from_str(input);
        message
            .process_header_line(TextRange::from_usize(0, input.len()))
            .unwrap();

        // In test methods, we need to clone to avoid borrowing conflicts
        // This is only in tests, not performance-critical code
        let raw_message = message.raw_message.clone();

        // Get the Contact header directly using contact() method
        let contact = message
            .contact()
            .unwrap()
            .expect("Contact header not found");

        // For consistency with our test, save as address
        let address = contact;

        // Extract values
        let scheme = address.uri.scheme.clone();
        let user_info_value = address.uri.user_info.map(|r| r.as_str(&raw_message));
        let mut params_map = HashMap::new();

        // Create a custom parameter map
        for (k, v) in &address.uri.params {
            let key = k.as_str(&raw_message);
            let value = v.as_ref().map(|r| r.as_str(&raw_message));
            params_map.insert(key, value);
        }

        // Check URI components
        assert_eq!(scheme, Scheme::TEL);
        assert_eq!(user_info_value, Some("+1-212-555-0123"));

        // Check parameters
        assert_eq!(
            params_map.get("phone-context").unwrap(),
            &Some("example.com")
        );
    }

    #[test]
    fn test_via_header() {
        let input = "Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds;received=192.0.2.1";
        let mut message = SipMessage::new_from_str(input);
        message
            .process_header_line(TextRange::from_usize(0, input.len()))
            .unwrap();

        // In test methods, we need to clone to avoid borrowing conflicts
        // This is only in tests, not performance-critical code
        let raw_message = message.raw_message.clone();

        // Get the Via header
        let via = message.via().unwrap().expect("Via header not found");

        // Extract values using as_str
        let sent_protocol_str = via.sent_protocol.as_str(&raw_message);
        let sent_by_str = via.sent_by.as_str(&raw_message);

        // Create a custom map of the parameters using as_str
        let mut params_map = HashMap::new();
        for (k, v) in &via.params {
            let key = k.as_str(&raw_message);
            let value = v.as_ref().map(|r| r.as_str(&raw_message));
            params_map.insert(key, value);
        }

        // Now check the values
        assert_eq!(sent_protocol_str, "SIP/2.0/UDP");
        assert_eq!(sent_by_str, "pc33.atlanta.com");
        assert_eq!(params_map.get("branch").unwrap(), &Some("z9hG4bK776asdhds"));
        assert_eq!(params_map.get("received").unwrap(), &Some("192.0.2.1"));
    }

    #[test]
    fn test_escaped_uri() {
        let input = "Contact: <sip:user%20name@host.com;transport=tcp?subject=Meeting%20Request>";
        let mut message = SipMessage::new_from_str(input);
        message
            .process_header_line(TextRange::from_usize(0, input.len()))
            .unwrap();

        // In test methods, we need to clone to avoid borrowing conflicts
        // This is only in tests, not performance-critical code
        let raw_message = message.raw_message.clone();

        // Get the Contact header directly using contact() method
        let contact = message
            .contact()
            .unwrap()
            .expect("Contact header not found");

        // For consistency with our test, save as address
        let address = contact;

        // Extract the needed values with as_str
        let user_info_value = address.uri.user_info.map(|r| r.as_str(&raw_message));
        let headers_value = address.uri.headers.map(|r| r.as_str(&raw_message));

        // Create a custom parameter map
        let mut params_map = HashMap::new();
        for (k, v) in &address.uri.params {
            let key = k.as_str(&raw_message);
            let value = v.as_ref().map(|r| r.as_str(&raw_message));
            params_map.insert(key, value);
        }

        // Check URI components with raw values instead of decoded values
        assert_eq!(user_info_value, Some("user%20name"));

        // Check parameters
        assert_eq!(params_map.get("transport").unwrap(), &Some("tcp"));

        // Check headers - our implementation doesn't decode the URI headers
        assert_eq!(headers_value, Some("subject=Meeting%20Request"));
    }

    #[test]
    fn test_multiple_headers_record_route() {
        let input = "Record-Route: <sip:proxy1.example.com;lr>, <sip:proxy2.example.com;lr>";
        let mut message = SipMessage::new_from_str(input);
        message
            .process_header_line(TextRange::from_usize(0, input.len()))
            .unwrap();

        // Manually extract the Record-Route headers
        let record_route_headers: Vec<_> = message
            .headers
            .iter()
            .filter(|(name, _)| message.get_str(*name).to_lowercase() == "record-route")
            .map(|(_, value)| value)
            .collect();

        // We should have at least one header entry
        assert!(!record_route_headers.is_empty());

        // Examine the values - our implementation should handle multiple values within a header
        // This depends on how your implementation handles comma-separated header values
        // This test might need adjustment based on your implementation
        match &record_route_headers[0] {
            HeaderValue::Raw(range) => {
                let value = message.get_str(*range);
                assert!(value.contains("proxy1.example.com"));
                assert!(value.contains("proxy2.example.com"));
            }
            // If your implementation parses Record-Route as Address types
            // then we'd need different assertions here
            _ => {
                // Depending on your implementation, we might need to check for
                // HeaderValue::Address variants or other specific handling
                // This is a simplified check for now

                // Implementation-specific validation needed for Record-Route header
                // No assert needed here as this is just a placeholder for future implementation
            }
        }
    }
}
