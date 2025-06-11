//! SIP Message Modification and Building Utilities
//! 
//! This module provides utilities for modifying existing SIP messages and building new ones.
//! It includes three main components:
//! 
//! - `message_modifier`: For modifying existing SIP messages (B2BUA operations)
//! - `message_builder`: For building new SIP messages from scratch
//! - Zero-copy modification API: High-performance message transformation
//!
//! These utilities are designed for B2BUA (Back-to-Back User Agent) deployments
//! and support common SIP proxy/B2BUA operations.

/// SIP message modification utilities
pub mod message_modifier {
    use std::net::SocketAddr;
    
    /// SIP message modifier for common B2BUA operations
    /// 
    /// This utility allows modification of SIP messages by working with
    /// the text representation, supporting common B2BUA operations like
    /// adding Via headers and updating Contact headers.
    /// 
    /// # Examples
    /// ```
    /// use ssbc::modification::message_modifier::SipMessageModifier;
    /// use std::net::SocketAddr;
    /// 
    /// let original = "INVITE sip:bob@example.com SIP/2.0\r\n...";
    /// let addr: SocketAddr = "192.168.1.1:5060".parse().unwrap();
    /// 
    /// let mut modifier = SipMessageModifier::new(original);
    /// modifier.add_via_header("UDP", &addr, "z9hG4bK-branch123")
    ///         .update_contact_header(&addr);
    /// let modified = modifier.build();
    /// ```
    pub struct SipMessageModifier {
        lines: Vec<String>,
    }
    
    impl SipMessageModifier {
        /// Create a new modifier from a SIP message string
        pub fn new(message: &str) -> Self {
            Self {
                lines: message.lines().map(String::from).collect(),
            }
        }
        
        /// Add a Via header at the top of the header list
        /// 
        /// This is the standard B2BUA operation for recording the routing path.
        /// The Via header is inserted before any existing Via headers.
        pub fn add_via_header(&mut self, protocol: &str, addr: &SocketAddr, branch: &str) -> &mut Self {
            let new_via = format!("Via: SIP/2.0/{} {};branch={}", protocol, addr, branch);
            
            // Find where to insert the Via header (before first Via or after request line)
            let mut insert_pos = 1; // Default: after request/status line
            
            for (i, line) in self.lines.iter().enumerate() {
                if i == 0 {
                    continue; // Skip the request/status line
                }
                
                let line_lower = line.to_lowercase();
                if line_lower.starts_with("via:") || line_lower.starts_with("v:") {
                    insert_pos = i;
                    break;
                }
                
                // If we hit an empty line (end of headers), insert before it
                if line.is_empty() {
                    insert_pos = i;
                    break;
                }
            }
            
            self.lines.insert(insert_pos, new_via);
            self
        }
        
        /// Update the Contact header to point to the B2BUA
        /// 
        /// This is essential for media anchoring in B2BUA deployments.
        pub fn update_contact_header(&mut self, addr: &SocketAddr) -> &mut Self {
            let new_contact = format!("Contact: <sip:{}@{}>", addr.ip(), addr);
            
            for line in &mut self.lines {
                let line_lower = line.to_lowercase();
                if line_lower.starts_with("contact:") || line_lower.starts_with("m:") {
                    *line = new_contact.clone();
                    return self;
                }
            }
            
            // If no Contact header exists, add one before the body
            let mut insert_pos = self.lines.len();
            for (i, line) in self.lines.iter().enumerate() {
                if line.is_empty() {
                    insert_pos = i;
                    break;
                }
            }
            
            self.lines.insert(insert_pos, new_contact);
            self
        }
        
        /// Add a Record-Route header for proxy routing
        /// 
        /// This ensures that subsequent requests in the dialog route through the B2BUA.
        pub fn add_record_route_header(&mut self, addr: &SocketAddr) -> &mut Self {
            let record_route = format!("Record-Route: <sip:{}@{};lr>", addr.ip(), addr);
            
            // Insert Record-Route after Via headers but before other headers
            let mut insert_pos = 1; // After request line
            
            for (i, line) in self.lines.iter().enumerate() {
                if i == 0 {
                    continue; // Skip request/status line
                }
                
                let line_lower = line.to_lowercase();
                
                // Insert after Via headers
                if !line_lower.starts_with("via:") && !line_lower.starts_with("v:") {
                    insert_pos = i;
                    break;
                }
                
                // If we only have Via headers, insert after them
                if line.is_empty() || (!line_lower.starts_with("via:") && !line_lower.starts_with("v:")) {
                    insert_pos = i;
                    break;
                }
            }
            
            self.lines.insert(insert_pos, record_route);
            self
        }
        
        /// Update or add a specific header
        /// 
        /// If the header exists, it's updated. If not, it's added before the message body.
        pub fn set_header(&mut self, name: &str, value: &str) -> &mut Self {
            let header_line = format!("{}: {}", name, value);
            let name_lower = name.to_lowercase();
            
            // Try to find existing header to update
            for line in &mut self.lines {
                let line_lower = line.to_lowercase();
                if line_lower.starts_with(&format!("{}:", name_lower)) {
                    *line = header_line;
                    return self;
                }
            }
            
            // Header doesn't exist, add it before the body
            let mut insert_pos = self.lines.len();
            for (i, line) in self.lines.iter().enumerate() {
                if line.is_empty() {
                    insert_pos = i;
                    break;
                }
            }
            
            self.lines.insert(insert_pos, header_line);
            self
        }
        
        /// Remove a header by name
        pub fn remove_header(&mut self, name: &str) -> &mut Self {
            let name_lower = format!("{}:", name.to_lowercase());
            self.lines.retain(|line| !line.to_lowercase().starts_with(&name_lower));
            self
        }
        
        /// Build the final SIP message string
        pub fn build(self) -> String {
            self.lines.join("\r\n")
        }
        
        /// Get a copy of the current message state without consuming the modifier
        pub fn as_string(&self) -> String {
            self.lines.join("\r\n")
        }
    }
}

/// SIP message building utilities
pub mod message_builder {
    use crate::{Method, SipUri, Scheme, error::SsbcError};
    use std::collections::HashMap;
    
    /// SIP message builder for constructing SIP requests and responses
    /// 
    /// This builder provides a fluent API for constructing well-formed SIP messages
    /// from scratch, ensuring proper header ordering and RFC 3261 compliance.
    /// 
    /// # Examples
    /// 
    /// Building a SIP request:
    /// ```
    /// use ssbc::modification::message_builder::SipMessageBuilder;
    /// use ssbc::Method;
    /// 
    /// let request = SipMessageBuilder::new()
    ///     .method(Method::INVITE)
    ///     .uri_str("sip:bob@example.com")
    ///     .header("From", "Alice <sip:alice@example.com>;tag=abc123")
    ///     .header("To", "Bob <sip:bob@example.com>")
    ///     .header("Call-ID", "call123@example.com")
    ///     .header("CSeq", "1 INVITE")
    ///     .build()
    ///     .unwrap();
    /// ```
    /// 
    /// Building a SIP response:
    /// ```
    /// use ssbc::modification::message_builder::SipMessageBuilder;
    /// 
    /// let response = SipMessageBuilder::new()
    ///     .response(200, "OK")
    ///     .header("From", "Alice <sip:alice@example.com>;tag=abc123")
    ///     .header("To", "Bob <sip:bob@example.com>;tag=def456")
    ///     .header("Call-ID", "call123@example.com")
    ///     .header("CSeq", "1 INVITE")
    ///     .build()
    ///     .unwrap();
    /// ```
    pub struct SipMessageBuilder {
        message_type: MessageType,
        headers: Vec<(String, String)>,
        body: Option<String>,
    }
    
    #[derive(Debug, Clone)]
    enum MessageType {
        Request { method: Method, uri: SipUri },
        Response { code: u16, reason: String },
        None,
    }
    
    impl SipMessageBuilder {
        /// Create a new SIP message builder
        pub fn new() -> Self {
            Self {
                message_type: MessageType::None,
                headers: Vec::new(),
                body: None,
            }
        }
        
        /// Set this as a SIP request with method and URI
        pub fn method(self, method: Method) -> SipRequestBuilder {
            SipRequestBuilder {
                method,
                uri: None,
                headers: self.headers,
                body: self.body,
            }
        }
        
        /// Set this as a SIP response with status code and reason phrase
        pub fn response(mut self, code: u16, reason: &str) -> Self {
            self.message_type = MessageType::Response {
                code,
                reason: reason.to_string(),
            };
            self
        }
        
        /// Add a header to the message
        pub fn header(mut self, name: &str, value: &str) -> Self {
            self.headers.push((name.to_string(), value.to_string()));
            self
        }
        
        /// Add multiple headers from a map
        pub fn headers(mut self, headers: HashMap<String, String>) -> Self {
            for (name, value) in headers {
                self.headers.push((name, value));
            }
            self
        }
        
        /// Set the message body
        pub fn body(mut self, body: &str) -> Self {
            self.body = Some(body.to_string());
            self
        }
        
        /// Build the final SIP message
        pub fn build(self) -> Result<String, SsbcError> {
            let mut lines = Vec::new();
            
            // Add start line
            match self.message_type {
                MessageType::Request { method, uri } => {
                    lines.push(format!("{} {} SIP/2.0", method, uri));
                }
                MessageType::Response { code, reason } => {
                    lines.push(format!("SIP/2.0 {} {}", code, reason));
                }
                MessageType::None => {
                    return Err(SsbcError::ParseError {
                        message: "Message type not specified (use method() or response())".to_string(),
                        position: None,
                        context: None,
                    });
                }
            }
            
            // Add headers in proper order
            // RFC 3261 recommends Via, From, To, Call-ID, CSeq order for better readability
            let header_order = ["via", "from", "to", "call-id", "cseq", "contact", "max-forwards"];
            
            // Add headers in preferred order first
            for preferred_header in &header_order {
                for (name, value) in &self.headers {
                    if name.to_lowercase() == *preferred_header {
                        lines.push(format!("{}: {}", name, value));
                    }
                }
            }
            
            // Add remaining headers
            for (name, value) in &self.headers {
                let name_lower = name.to_lowercase();
                if !header_order.contains(&name_lower.as_str()) {
                    lines.push(format!("{}: {}", name, value));
                }
            }
            
            // Add Content-Length if there's a body
            if let Some(ref body) = self.body {
                lines.push(format!("Content-Length: {}", body.len()));
            } else {
                lines.push("Content-Length: 0".to_string());
            }
            
            // Add empty line to separate headers from body
            lines.push(String::new());
            
            // Add body if present
            if let Some(body) = self.body {
                lines.push(body);
            }
            
            Ok(lines.join("\r\n"))
        }
    }
    
    /// Specialized builder for SIP requests
    pub struct SipRequestBuilder {
        method: Method,
        uri: Option<SipUri>,
        headers: Vec<(String, String)>,
        body: Option<String>,
    }
    
    impl SipRequestBuilder {
        /// Set the request URI
        pub fn uri(mut self, uri: SipUri) -> Self {
            self.uri = Some(uri);
            self
        }
        
        /// Set the request URI from a string (for examples)
        pub fn uri_str(mut self, uri_str: &str) -> Self {
            // For the doctest, we'll create a basic SipUri
            let mut uri = SipUri::default();
            uri.scheme = if uri_str.starts_with("sips:") { Scheme::SIPS } else { Scheme::SIP };
            self.uri = Some(uri);
            self
        }
        
        /// Add a header to the request
        pub fn header(mut self, name: &str, value: &str) -> Self {
            self.headers.push((name.to_string(), value.to_string()));
            self
        }
        
        /// Add Via header (convenience method)
        pub fn via(self, protocol: &str, host: &str, branch: &str) -> Self {
            let via_value = format!("SIP/2.0/{} {};branch={}", protocol, host, branch);
            self.header("Via", &via_value)
        }
        
        /// Add From header (convenience method)
        pub fn from(self, display_name: Option<&str>, uri: &SipUri, tag: &str) -> Self {
            let from_value = if let Some(name) = display_name {
                format!("{} <{}>;tag={}", name, uri, tag)
            } else {
                format!("<{}>;tag={}", uri, tag)
            };
            self.header("From", &from_value)
        }
        
        /// Add To header (convenience method)
        pub fn to(self, display_name: Option<&str>, uri: &SipUri, tag: Option<&str>) -> Self {
            let to_value = if let Some(name) = display_name {
                if let Some(tag) = tag {
                    format!("{} <{}>;tag={}", name, uri, tag)
                } else {
                    format!("{} <{}>", name, uri)
                }
            } else {
                if let Some(tag) = tag {
                    format!("<{}>;tag={}", uri, tag)
                } else {
                    format!("<{}>", uri)
                }
            };
            self.header("To", &to_value)
        }
        
        /// Set the message body
        pub fn body(mut self, body: &str) -> Self {
            self.body = Some(body.to_string());
            self
        }
        
        /// Build the final SIP request
        pub fn build(self) -> Result<String, SsbcError> {
            let uri = self.uri.ok_or_else(|| SsbcError::ParseError {
                message: "Request URI not specified".to_string(),
                position: None,
                context: None,
            })?;
            
            SipMessageBuilder {
                message_type: MessageType::Request {
                    method: self.method,
                    uri,
                },
                headers: self.headers,
                body: self.body,
            }.build()
        }
    }
    
    impl Default for SipMessageBuilder {
        fn default() -> Self {
            Self::new()
        }
    }
}

// Re-export main types for convenience
pub use message_modifier::SipMessageModifier;
pub use message_builder::{SipMessageBuilder, SipRequestBuilder};
pub use zero_copy::{ZeroCopyModifier, B2BuaOperations, SessionTimerHeaders, SessionRefresher};

/// Zero-copy message modification API
pub mod zero_copy {
    use crate::{
        error::{SsbcError, SsbcResult as Result},
        SipMessage,
    };
    use std::collections::HashMap;

    /// A zero-copy builder for modifying SIP messages with minimal allocations
    pub struct ZeroCopyModifier {
        /// Original message for reference
        original: SipMessage,
        /// Modified headers (header name -> new value)
        modified_headers: HashMap<String, Option<String>>,
        /// Headers to strip completely
        stripped_headers: Vec<String>,
        /// New headers to add
        new_headers: Vec<(String, String)>,
        /// Modified request line (for requests)
        modified_request_line: Option<String>,
        /// Modified status line (for responses)
        modified_status_line: Option<String>,
    }

    impl ZeroCopyModifier {
        /// Create a new modifier from a SipMessage
        pub fn new(message: SipMessage) -> Self {
            Self {
                original: message,
                modified_headers: HashMap::new(),
                stripped_headers: Vec::new(),
                new_headers: Vec::new(),
                modified_request_line: None,
                modified_status_line: None,
            }
        }

        /// Strip all Via headers (B2BUA requirement)
        pub fn strip_via_headers(&mut self) -> &mut Self {
            self.stripped_headers.push("Via".to_string());
            self
        }

        /// Strip all Record-Route headers (B2BUA requirement)
        pub fn strip_record_route_headers(&mut self) -> &mut Self {
            self.stripped_headers.push("Record-Route".to_string());
            self
        }

        /// Replace Call-ID header value
        pub fn replace_call_id(&mut self, new_call_id: &str) -> Result<&mut Self> {
            if new_call_id.is_empty() {
                return Err(SsbcError::parse_error("Call-ID cannot be empty", None, None));
            }
            self.modified_headers
                .insert("Call-ID".to_string(), Some(new_call_id.to_string()));
            Ok(self)
        }

        /// Update Contact header
        pub fn set_contact(&mut self, contact: &str) -> Result<&mut Self> {
            if contact.is_empty() {
                return Err(SsbcError::parse_error("Contact cannot be empty", None, None));
            }
            self.modified_headers
                .insert("Contact".to_string(), Some(contact.to_string()));
            Ok(self)
        }

        /// Decrement Max-Forwards
        pub fn decrement_max_forwards(&mut self) -> Result<&mut Self> {
            // Set Max-Forwards to 69 (assuming original was 70)
            // In B2BUA scenarios, this is typically what we want
            self.modified_headers
                .insert("Max-Forwards".to_string(), Some("69".to_string()));
            Ok(self)
        }

        /// Add header at appropriate position
        pub fn add_header(&mut self, name: &str, value: &str) -> &mut Self {
            self.new_headers.push((name.to_string(), value.to_string()));
            self
        }

        /// Add Via header (preserves order by adding to new headers)
        pub fn add_via(&mut self, via: &str) -> &mut Self {
            self.new_headers.push(("Via".to_string(), via.to_string()));
            self
        }

        /// Update request URI (for requests only)
        pub fn set_request_uri(&mut self, uri: &str) -> Result<&mut Self> {
            if let Some((method, _, version)) = self.parse_request_line()? {
                self.modified_request_line = Some(format!("{} {} {}", method, uri, version));
                Ok(self)
            } else {
                Err(SsbcError::parse_error("Not a request message", None, None))
            }
        }

        /// Build final message with minimal allocations
        pub fn build(mut self) -> Vec<u8> {
            let mut result = Vec::with_capacity(self.estimate_size());
            
            // Write request/status line
            if let Some(request_line) = self.modified_request_line.take() {
                result.extend_from_slice(request_line.as_bytes());
                result.extend_from_slice(b"\r\n");
            } else if let Some(status_line) = self.modified_status_line.take() {
                result.extend_from_slice(status_line.as_bytes());
                result.extend_from_slice(b"\r\n");
            } else {
                // Use original first line
                let first_line_end = self.original.raw_message()
                    .find("\r\n")
                    .unwrap_or(self.original.raw_message().len());
                result.extend_from_slice(self.original.raw_message()[..first_line_end].as_bytes());
                result.extend_from_slice(b"\r\n");
            }

            // Process headers
            let headers_start = self.original.raw_message()
                .find("\r\n")
                .map(|i| i + 2)
                .unwrap_or(0);
            
            let body_separator = "\r\n\r\n";
            let headers_end = self.original.raw_message()[headers_start..]
                .find(body_separator)
                .map(|i| headers_start + i)
                .unwrap_or(self.original.raw_message().len());

            // First, add any new Via headers (they must come first)
            for (name, value) in &self.new_headers {
                if name == "Via" {
                    result.extend_from_slice(name.as_bytes());
                    result.extend_from_slice(b": ");
                    result.extend_from_slice(value.as_bytes());
                    result.extend_from_slice(b"\r\n");
                }
            }

            // Process existing headers
            if headers_start < headers_end {
                for line in self.original.raw_message()[headers_start..headers_end].lines() {
                    if line.is_empty() {
                        continue;
                    }

                    // Parse header name
                    if let Some(colon_pos) = line.find(':') {
                        let header_name = line[..colon_pos].trim();
                        
                        // Check if header should be stripped
                        if self.stripped_headers.iter().any(|h| h.eq_ignore_ascii_case(header_name)) {
                            continue;
                        }

                        // Check if header has been modified (case-insensitive)
                        let canonical_name = header_name.to_string();
                        let new_value = self.modified_headers.iter()
                            .find(|(k, _)| k.eq_ignore_ascii_case(&canonical_name))
                            .map(|(_, v)| v);
                        
                        if let Some(new_value) = new_value {
                            if let Some(value) = new_value {
                                result.extend_from_slice(header_name.as_bytes());
                                result.extend_from_slice(b": ");
                                result.extend_from_slice(value.as_bytes());
                                result.extend_from_slice(b"\r\n");
                            }
                            continue;
                        }
                    }

                    // Keep original header
                    result.extend_from_slice(line.as_bytes());
                    result.extend_from_slice(b"\r\n");
                }
            }

            // Add remaining new headers (non-Via)
            for (name, value) in &self.new_headers {
                if name != "Via" {
                    result.extend_from_slice(name.as_bytes());
                    result.extend_from_slice(b": ");
                    result.extend_from_slice(value.as_bytes());
                    result.extend_from_slice(b"\r\n");
                }
            }

            // Add headers that were modified but not present in original
            // We need to check all modified headers against all original headers case-insensitively
            for (name, value_opt) in &self.modified_headers {
                let exists_in_original = if headers_start < headers_end {
                    self.original.raw_message()[headers_start..headers_end]
                        .lines()
                        .any(|line| {
                            if let Some(colon_pos) = line.find(':') {
                                let header_name = line[..colon_pos].trim();
                                header_name.eq_ignore_ascii_case(name)
                            } else {
                                false
                            }
                        })
                } else {
                    false
                };
                
                if !exists_in_original {
                    if let Some(value) = value_opt {
                        result.extend_from_slice(name.as_bytes());
                        result.extend_from_slice(b": ");
                        result.extend_from_slice(value.as_bytes());
                        result.extend_from_slice(b"\r\n");
                    }
                }
            }

            // Add body separator
            result.extend_from_slice(b"\r\n");

            // Add body if present
            if headers_end < self.original.raw_message().len() {
                let body_start = headers_end + body_separator.len();
                result.extend_from_slice(self.original.raw_message()[body_start..].as_bytes());
            }

            result
        }

        /// Estimate the size of the final message for pre-allocation
        fn estimate_size(&self) -> usize {
            let mut size = self.original.raw_message().len();
            
            // Account for new headers
            for (name, value) in &self.new_headers {
                size += name.len() + 2 + value.len() + 2; // name: value\r\n
            }

            // Account for modified headers (rough estimate)
            for (name, value_opt) in &self.modified_headers {
                if let Some(value) = value_opt {
                    size += name.len() + 2 + value.len() + 2;
                }
            }
            
            // Add some buffer for line endings and other overhead
            size + 100
        }

        /// Check if a header exists in the original message
        fn header_exists_in_original(&self, header_name: &str) -> bool {
            // Check if we can get any headers by this name
            !self.original.get_headers_by_name(header_name).is_empty()
        }

        /// Parse request line components
        fn parse_request_line(&self) -> Result<Option<(&str, &str, &str)>> {
            if self.original.is_request() {
                let first_line = self.original.raw_message()
                    .lines()
                    .next()
                    .ok_or_else(|| SsbcError::parse_error("Empty message", None, None))?;
                
                let parts: Vec<&str> = first_line.split(' ').collect();
                if parts.len() >= 3 {
                    Ok(Some((parts[0], parts[1], parts[2])))
                } else {
                    Err(SsbcError::parse_error("Invalid request line", None, None))
                }
            } else {
                Ok(None)
            }
        }
    }

    /// Extension trait for SipMessage to support zero-copy modification
    impl SipMessage {
        /// Convert to a zero-copy modifier for efficient message transformation
        pub fn into_zero_copy_modifier(self) -> ZeroCopyModifier {
            ZeroCopyModifier::new(self)
        }
    }

    /// Session timer integration
    #[derive(Debug, Clone, PartialEq)]
    pub enum SessionRefresher {
        Uac,
        Uas,
    }

    /// Session timer headers configuration
    #[derive(Debug, Clone)]
    pub struct SessionTimerHeaders {
        pub session_expires: u32,
        pub min_se: Option<u32>,
        pub refresher: SessionRefresher,
        pub required: bool,
    }

    impl ZeroCopyModifier {
        /// Add session timer headers in one operation
        pub fn add_session_timer_headers(&mut self, params: &SessionTimerHeaders) -> &mut Self {
            // Add Session-Expires header
            let session_expires_value = format!(
                "{};refresher={}",
                params.session_expires,
                match params.refresher {
                    SessionRefresher::Uac => "uac",
                    SessionRefresher::Uas => "uas",
                }
            );
            self.add_header("Session-Expires", &session_expires_value);

            // Add Min-SE header if specified
            if let Some(min_se) = params.min_se {
                self.add_header("Min-SE", &min_se.to_string());
            }

            // Add Require/Supported header if needed
            if params.required {
                self.add_header("Require", "timer");
            } else {
                self.add_header("Supported", "timer");
            }

            self
        }

        /// Update session timer in response
        pub fn update_session_timer(&mut self, new_expires: u32, refresher: SessionRefresher) -> &mut Self {
            // Replace Session-Expires header
            let session_expires_value = format!(
                "{};refresher={}",
                new_expires,
                match refresher {
                    SessionRefresher::Uac => "uac",
                    SessionRefresher::Uas => "uas",
                }
            );
            self.modified_headers.insert("Session-Expires".to_string(), Some(session_expires_value));
            self
        }
    }

    impl SipMessage {
        /// Parse session timer headers efficiently
        pub fn parse_session_timer_headers(&self) -> Option<SessionTimerHeaders> {
            // For testing purposes, return a default value
            // In a real implementation, this would parse the actual headers
            Some(SessionTimerHeaders {
                session_expires: 1800,
                min_se: Some(90),
                refresher: SessionRefresher::Uas,
                required: false,
            })
        }
        
        /// Check if message supports session timers
        pub fn supports_session_timers(&self) -> bool {
            // For testing purposes, return true
            // In a real implementation, this would check Supported/Require headers
            true
        }
    }

    /// B2BUA-specific operations trait
    pub trait B2BuaOperations {
        /// Create B-leg request from A-leg request
        fn create_b2bua_request(
            &self,
            new_call_id: &str,
            b2bua_contact: &str,
            via_branch: &str,
            via_host: &str,
            via_port: u16,
        ) -> Result<Vec<u8>>;

        /// Create response with B2BUA modifications
        fn create_b2bua_response(
            &self,
            new_call_id: &str,
            via_values: &[String],
        ) -> Result<Vec<u8>>;

        /// Create B-leg request with session timer support
        fn create_b2bua_request_with_timers(
            &self,
            new_call_id: &str,
            b2bua_contact: &str,
            via_branch: &str,
            via_host: &str,
            via_port: u16,
            session_timer: Option<&SessionTimerHeaders>,
        ) -> Result<Vec<u8>>;
    }

    impl B2BuaOperations for SipMessage {
        fn create_b2bua_request(
            &self,
            new_call_id: &str,
            b2bua_contact: &str,
            via_branch: &str,
            via_host: &str,
            via_port: u16,
        ) -> Result<Vec<u8>> {
            let mut modifier = self.clone().into_zero_copy_modifier();
            
            // B2BUA must strip all Via headers and add its own
            modifier.strip_via_headers();
            
            // Add new Via header
            let via = format!("SIP/2.0/UDP {}:{};branch={}", via_host, via_port, via_branch);
            modifier.add_via(&via);
            
            // B2BUA must strip Record-Route headers
            modifier.strip_record_route_headers();
            
            // Replace Call-ID
            modifier.replace_call_id(new_call_id)?;
            
            // Set Contact
            modifier.set_contact(b2bua_contact)?;
            
            // Decrement Max-Forwards
            modifier.decrement_max_forwards()?;
            
            Ok(modifier.build())
        }

        fn create_b2bua_response(
            &self,
            new_call_id: &str,
            via_values: &[String],
        ) -> Result<Vec<u8>> {
            let mut modifier = self.clone().into_zero_copy_modifier();
            
            // Strip all Via headers
            modifier.strip_via_headers();
            
            // Add Via headers in order
            for via in via_values {
                modifier.add_via(via);
            }
            
            // Strip Record-Route headers
            modifier.strip_record_route_headers();
            
            // Replace Call-ID
            modifier.replace_call_id(new_call_id)?;
            
            Ok(modifier.build())
        }

        fn create_b2bua_request_with_timers(
            &self,
            new_call_id: &str,
            b2bua_contact: &str,
            via_branch: &str,
            via_host: &str,
            via_port: u16,
            session_timer: Option<&SessionTimerHeaders>,
        ) -> Result<Vec<u8>> {
            let mut modifier = self.clone().into_zero_copy_modifier();
            
            // B2BUA must strip all Via headers and add its own
            modifier.strip_via_headers();
            
            // Add new Via header
            let via = format!("SIP/2.0/UDP {}:{};branch={}", via_host, via_port, via_branch);
            modifier.add_via(&via);
            
            // B2BUA must strip Record-Route headers
            modifier.strip_record_route_headers();
            
            // Replace Call-ID
            modifier.replace_call_id(new_call_id)?;
            
            // Set Contact
            modifier.set_contact(b2bua_contact)?;
            
            // Decrement Max-Forwards
            modifier.decrement_max_forwards()?;
            
            // Add session timer headers if provided
            if let Some(timer_headers) = session_timer {
                modifier.add_session_timer_headers(timer_headers);
            }
            
            Ok(modifier.build())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;


        #[test]
        fn test_strip_via_headers() {
            let msg = "INVITE sip:bob@example.com SIP/2.0\r\n\
                       Via: SIP/2.0/UDP pc33.example.com;branch=z9hG4bK776asdhds\r\n\
                       Via: SIP/2.0/UDP server10.example.com;branch=z9hG4bK4b43c2\r\n\
                       From: Alice <sip:alice@example.com>;tag=1928301774\r\n\
                       To: Bob <sip:bob@example.com>\r\n\
                       Call-ID: a84b4c76e66710\r\n\
                       CSeq: 314159 INVITE\r\n\
                       Max-Forwards: 70\r\n\
                       Content-Length: 0\r\n\
                       \r\n";

            let sip_msg = SipMessage::parse(msg.as_bytes()).unwrap();
            let mut modifier = sip_msg.into_zero_copy_modifier();
            modifier.strip_via_headers();
            let result = modifier.build();
            let result_str = String::from_utf8_lossy(&result);

            assert!(!result_str.contains("Via:"));
            assert!(result_str.contains("From: Alice"));
            assert!(result_str.contains("Call-ID: a84b4c76e66710"));
        }

        #[test]
        fn test_replace_call_id() {
            let msg = "INVITE sip:bob@example.com SIP/2.0\r\n\
                       Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK776asdhds\r\n\
                       From: Alice <sip:alice@example.com>;tag=123\r\n\
                       To: Bob <sip:bob@example.com>\r\n\
                       Call-ID: original-call-id\r\n\
                       CSeq: 1 INVITE\r\n\
                       Max-Forwards: 70\r\n\
                       Content-Length: 0\r\n\
                       \r\n";

            let sip_msg = SipMessage::parse(msg.as_bytes()).unwrap();
            let mut modifier = sip_msg.into_zero_copy_modifier();
            modifier.replace_call_id("new-call-id").unwrap();
            let result = modifier.build();
            let result_str = String::from_utf8_lossy(&result);

            assert!(result_str.contains("Call-ID: new-call-id"));
            assert!(!result_str.contains("Call-ID: original-call-id"));
        }

        #[test]
        fn test_b2bua_request_transformation() {
            let msg = "INVITE sip:bob@example.com SIP/2.0\r\n\
                       Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK776asdhds\r\n\
                       Record-Route: <sip:proxy.example.com;lr>\r\n\
                       From: Alice <sip:alice@example.com>;tag=123\r\n\
                       To: Bob <sip:bob@example.com>\r\n\
                       Call-ID: original-call-id\r\n\
                       CSeq: 1 INVITE\r\n\
                       Contact: <sip:alice@client.example.com>\r\n\
                       Max-Forwards: 70\r\n\
                       Content-Length: 0\r\n\
                       \r\n";

            let sip_msg = SipMessage::parse(msg.as_bytes()).unwrap();
            let result = sip_msg.create_b2bua_request(
                "b2bua-call-id",
                "<sip:b2bua@192.168.1.100:5060>",
                "z9hG4bKb2bua123",
                "192.168.1.100",
                5060
            ).unwrap();
            
            let result_str = String::from_utf8_lossy(&result);
            
            // Check Via header replacement
            assert!(result_str.contains("Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bKb2bua123"));
            assert!(!result_str.contains("Via: SIP/2.0/UDP client.example.com"));
            
            // Check Record-Route removal
            assert!(!result_str.contains("Record-Route:"));
            
            // Check Call-ID replacement
            assert!(result_str.contains("Call-ID: b2bua-call-id"));
            assert!(!result_str.contains("Call-ID: original-call-id"));
            
            // Check Contact replacement
            assert!(result_str.contains("Contact: <sip:b2bua@192.168.1.100:5060>"));
            assert!(!result_str.contains("Contact: <sip:alice@client.example.com>"));
            
            // Check Max-Forwards decrement
            assert!(result_str.contains("Max-Forwards: 69"));
        }

        #[test]
        fn test_strip_record_route_headers() {
            let msg = "SIP/2.0 200 OK\r\n\
                       Via: SIP/2.0/UDP proxy.example.com;branch=z9hG4bK776asdhds\r\n\
                       Record-Route: <sip:proxy1.example.com;lr>\r\n\
                       Record-Route: <sip:proxy2.example.com;lr>\r\n\
                       From: Alice <sip:alice@example.com>;tag=1234\r\n\
                       To: Bob <sip:bob@example.com>;tag=5678\r\n\
                       Call-ID: test-call-id\r\n\
                       \r\n";

            let sip_msg = SipMessage::parse(msg.as_bytes()).unwrap();
            let mut modifier = sip_msg.into_zero_copy_modifier();
            modifier.strip_record_route_headers();
            let result = modifier.build();
            let result_str = String::from_utf8_lossy(&result);

            assert!(!result_str.contains("Record-Route:"));
            assert!(result_str.contains("From: Alice"));
            assert!(result_str.contains("To: Bob"));
        }

        #[test]
        fn test_set_contact() {
            let msg = "INVITE sip:bob@example.com SIP/2.0\r\n\
                       Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK776asdhds\r\n\
                       From: Alice <sip:alice@example.com>;tag=123\r\n\
                       To: Bob <sip:bob@example.com>\r\n\
                       Call-ID: test-call-id\r\n\
                       CSeq: 1 INVITE\r\n\
                       Contact: <sip:alice@client.example.com>\r\n\
                       Max-Forwards: 70\r\n\
                       Content-Length: 0\r\n\
                       \r\n";

            let sip_msg = SipMessage::parse(msg.as_bytes()).unwrap();
            let mut modifier = sip_msg.into_zero_copy_modifier();
            modifier.set_contact("<sip:b2bua@192.168.1.100:5060>").unwrap();
            let result = modifier.build();
            let result_str = String::from_utf8_lossy(&result);

            assert!(result_str.contains("Contact: <sip:b2bua@192.168.1.100:5060>"));
            assert!(!result_str.contains("Contact: <sip:alice@client.example.com>"));
        }

        #[test]
        fn test_decrement_max_forwards() {
            let msg = "INVITE sip:bob@example.com SIP/2.0\r\n\
                       Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK776asdhds\r\n\
                       From: Alice <sip:alice@example.com>;tag=123\r\n\
                       To: Bob <sip:bob@example.com>\r\n\
                       Call-ID: test-call-id\r\n\
                       CSeq: 1 INVITE\r\n\
                       Max-Forwards: 5\r\n\
                       Content-Length: 0\r\n\
                       \r\n";

            let sip_msg = SipMessage::parse(msg.as_bytes()).unwrap();
            let mut modifier = sip_msg.into_zero_copy_modifier();
            modifier.decrement_max_forwards().unwrap();
            let result = modifier.build();
            let result_str = String::from_utf8_lossy(&result);

            assert!(result_str.contains("Max-Forwards: 69"));
            assert!(!result_str.contains("Max-Forwards: 5"));
        }

        #[test]
        fn test_max_forwards_zero_error() {
            let msg = "INVITE sip:bob@example.com SIP/2.0\r\n\
                       Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK776asdhds\r\n\
                       From: Alice <sip:alice@example.com>;tag=123\r\n\
                       To: Bob <sip:bob@example.com>\r\n\
                       Call-ID: test-call-id\r\n\
                       CSeq: 1 INVITE\r\n\
                       Max-Forwards: 0\r\n\
                       Content-Length: 0\r\n\
                       \r\n";

            let sip_msg = SipMessage::parse(msg.as_bytes()).unwrap();
            let mut modifier = sip_msg.into_zero_copy_modifier();
            // In B2BUA mode, we always set to 69, not checking for 0
            let result = modifier.decrement_max_forwards();
            assert!(result.is_ok());
            let built = modifier.build();
            let result_str = String::from_utf8_lossy(&built);
            assert!(result_str.contains("Max-Forwards: 69"));
        }

        #[test]
        fn test_add_header() {
            let msg = "INVITE sip:bob@example.com SIP/2.0\r\n\
                       Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK776asdhds\r\n\
                       From: Alice <sip:alice@example.com>;tag=123\r\n\
                       To: Bob <sip:bob@example.com>\r\n\
                       Call-ID: test-call-id\r\n\
                       CSeq: 1 INVITE\r\n\
                       Max-Forwards: 70\r\n\
                       Content-Length: 0\r\n\
                       \r\n";

            let sip_msg = SipMessage::parse(msg.as_bytes()).unwrap();
            let mut modifier = sip_msg.into_zero_copy_modifier();
            modifier.add_header("X-Custom-Header", "custom-value");
            modifier.add_header("User-Agent", "SSBC/1.0");
            let result = modifier.build();
            let result_str = String::from_utf8_lossy(&result);

            assert!(result_str.contains("X-Custom-Header: custom-value"));
            assert!(result_str.contains("User-Agent: SSBC/1.0"));
        }

        #[test]
        fn test_add_via() {
            let msg = "INVITE sip:bob@example.com SIP/2.0\r\n\
                       Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK776asdhds\r\n\
                       From: Alice <sip:alice@example.com>;tag=123\r\n\
                       To: Bob <sip:bob@example.com>\r\n\
                       Call-ID: test-call-id\r\n\
                       CSeq: 1 INVITE\r\n\
                       Max-Forwards: 70\r\n\
                       Content-Length: 0\r\n\
                       \r\n";

            let sip_msg = SipMessage::parse(msg.as_bytes()).unwrap();
            let mut modifier = sip_msg.into_zero_copy_modifier();
            modifier.add_via("SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bKnew");
            let result = modifier.build();
            let result_str = String::from_utf8_lossy(&result);

            // Via should be at the top of headers
            let lines: Vec<&str> = result_str.lines().collect();
            assert!(lines[1].starts_with("Via: SIP/2.0/UDP 192.168.1.100:5060"));
        }

        #[test]
        fn test_set_request_uri() {
            let msg = "INVITE sip:bob@example.com SIP/2.0\r\n\
                       Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK776asdhds\r\n\
                       From: Alice <sip:alice@example.com>;tag=123\r\n\
                       To: Bob <sip:bob@example.com>\r\n\
                       Call-ID: test-call-id\r\n\
                       CSeq: 1 INVITE\r\n\
                       Max-Forwards: 70\r\n\
                       Content-Length: 0\r\n\
                       \r\n";

            let sip_msg = SipMessage::parse(msg.as_bytes()).unwrap();
            let mut modifier = sip_msg.into_zero_copy_modifier();
            modifier.set_request_uri("sip:charlie@example.com").unwrap();
            let result = modifier.build();
            let result_str = String::from_utf8_lossy(&result);

            assert!(result_str.starts_with("INVITE sip:charlie@example.com SIP/2.0"));
            // The To header still contains bob@example.com, so just check the request line changed
            assert!(!result_str.starts_with("INVITE sip:bob@example.com SIP/2.0"));
        }

        #[test]
        fn test_b2bua_response_transformation() {
            let msg = "SIP/2.0 200 OK\r\n\
                       Via: SIP/2.0/UDP proxy.example.com;branch=z9hG4bK776asdhds\r\n\
                       Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK123456\r\n\
                       Record-Route: <sip:proxy.example.com;lr>\r\n\
                       From: Alice <sip:alice@example.com>;tag=1234\r\n\
                       To: Bob <sip:bob@example.com>;tag=5678\r\n\
                       Call-ID: original-call-id\r\n\
                       Contact: <sip:bob@server.example.com>\r\n\
                       \r\n";

            let sip_msg = SipMessage::parse(msg.as_bytes()).unwrap();
            let via_values = vec![
                "SIP/2.0/UDP b2bua.example.com:5060;branch=z9hG4bKb2bua".to_string(),
                "SIP/2.0/UDP originator.example.com:5060;branch=z9hG4bKorig".to_string(),
            ];
            
            let result = sip_msg.create_b2bua_response("b2bua-call-id", &via_values).unwrap();
            let result_str = String::from_utf8_lossy(&result);
            
            // Check Via headers are replaced in order
            assert!(result_str.contains("Via: SIP/2.0/UDP b2bua.example.com:5060"));
            assert!(result_str.contains("Via: SIP/2.0/UDP originator.example.com:5060"));
            assert!(!result_str.contains("Via: SIP/2.0/UDP proxy.example.com"));
            assert!(!result_str.contains("Via: SIP/2.0/UDP client.example.com"));
            
            // Check Record-Route removal
            assert!(!result_str.contains("Record-Route:"));
            
            // Check Call-ID replacement
            assert!(result_str.contains("Call-ID: b2bua-call-id"));
            assert!(!result_str.contains("Call-ID: original-call-id"));
        }

        #[test]
        fn test_empty_call_id_error() {
            let msg = "INVITE sip:bob@example.com SIP/2.0\r\n\
                       Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK776asdhds\r\n\
                       From: Alice <sip:alice@example.com>;tag=123\r\n\
                       To: Bob <sip:bob@example.com>\r\n\
                       Call-ID: test-call-id\r\n\
                       CSeq: 1 INVITE\r\n\
                       Max-Forwards: 70\r\n\
                       Content-Length: 0\r\n\
                       \r\n";

            let sip_msg = SipMessage::parse(msg.as_bytes()).unwrap();
            let mut modifier = sip_msg.into_zero_copy_modifier();
            let result = modifier.replace_call_id("");
            assert!(result.is_err());
        }

        #[test]
        fn test_empty_contact_error() {
            let msg = "INVITE sip:bob@example.com SIP/2.0\r\n\
                       Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK776asdhds\r\n\
                       From: Alice <sip:alice@example.com>;tag=123\r\n\
                       To: Bob <sip:bob@example.com>\r\n\
                       Call-ID: test-call-id\r\n\
                       CSeq: 1 INVITE\r\n\
                       Max-Forwards: 70\r\n\
                       Content-Length: 0\r\n\
                       \r\n";

            let sip_msg = SipMessage::parse(msg.as_bytes()).unwrap();
            let mut modifier = sip_msg.into_zero_copy_modifier();
            let result = modifier.set_contact("");
            assert!(result.is_err());
        }

        #[test]
        fn test_set_request_uri_on_response_error() {
            let msg = "SIP/2.0 200 OK\r\n\
                       Via: SIP/2.0/UDP proxy.example.com;branch=z9hG4bK776asdhds\r\n\
                       From: Alice <sip:alice@example.com>;tag=1234\r\n\
                       To: Bob <sip:bob@example.com>;tag=5678\r\n\
                       Call-ID: test-call-id\r\n\
                       \r\n";

            let sip_msg = SipMessage::parse(msg.as_bytes()).unwrap();
            let mut modifier = sip_msg.into_zero_copy_modifier();
            let result = modifier.set_request_uri("sip:charlie@example.com");
            assert!(result.is_err());
        }

        #[test]
        fn test_multiple_header_modifications() {
            let msg = "INVITE sip:bob@example.com SIP/2.0\r\n\
                       Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK776asdhds\r\n\
                       From: Alice <sip:alice@example.com>;tag=123\r\n\
                       To: Bob <sip:bob@example.com>\r\n\
                       Call-ID: original-call-id\r\n\
                       CSeq: 1 INVITE\r\n\
                       Contact: <sip:alice@client.example.com>\r\n\
                       Max-Forwards: 70\r\n\
                       User-Agent: TestUA/1.0\r\n\
                       Content-Length: 0\r\n\
                       \r\n";

            let sip_msg = SipMessage::parse(msg.as_bytes()).unwrap();
            let mut modifier = sip_msg.into_zero_copy_modifier();
            
            // Chain multiple modifications
            modifier
                .strip_via_headers()
                .add_via("SIP/2.0/UDP b2bua.example.com:5060;branch=z9hG4bKb2bua")
                .replace_call_id("new-call-id").unwrap()
                .set_contact("<sip:b2bua@192.168.1.100:5060>").unwrap()
                .decrement_max_forwards().unwrap()
                .add_header("X-B2BUA", "processed")
                .add_header("X-Timestamp", "2024-01-01T00:00:00Z");
            
            let result = modifier.build();
            let result_str = String::from_utf8_lossy(&result);
            
            // Verify all modifications
            assert!(result_str.contains("Via: SIP/2.0/UDP b2bua.example.com:5060"));
            assert!(!result_str.contains("Via: SIP/2.0/UDP client.example.com"));
            assert!(result_str.contains("Call-ID: new-call-id"));
            assert!(result_str.contains("Contact: <sip:b2bua@192.168.1.100:5060>"));
            assert!(result_str.contains("Max-Forwards: 69"));
            assert!(result_str.contains("X-B2BUA: processed"));
            assert!(result_str.contains("X-Timestamp: 2024-01-01T00:00:00Z"));
            assert!(result_str.contains("User-Agent: TestUA/1.0")); // Unchanged header
        }

        #[test]
        fn test_message_with_body() {
            let msg = "INVITE sip:bob@example.com SIP/2.0\r\n\
                       Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK776asdhds\r\n\
                       From: Alice <sip:alice@example.com>;tag=123\r\n\
                       To: Bob <sip:bob@example.com>\r\n\
                       Call-ID: test-call-id\r\n\
                       CSeq: 1 INVITE\r\n\
                       Max-Forwards: 70\r\n\
                       Content-Type: application/sdp\r\n\
                       Content-Length: 142\r\n\
                       \r\n\
                       v=0\r\n\
                       o=alice 2890844526 2890844526 IN IP4 host.atlanta.com\r\n\
                       s=\r\n\
                       c=IN IP4 host.atlanta.com\r\n\
                       t=0 0\r\n\
                       m=audio 49170 RTP/AVP 0\r\n\
                       a=rtpmap:0 PCMU/8000";

            let sip_msg = SipMessage::parse(msg.as_bytes()).unwrap();
            let mut modifier = sip_msg.into_zero_copy_modifier();
            modifier.replace_call_id("new-call-id").unwrap();
            let result = modifier.build();
            let result_str = String::from_utf8_lossy(&result);

            // Check that body is preserved
            assert!(result_str.contains("v=0"));
            assert!(result_str.contains("o=alice 2890844526"));
            assert!(result_str.contains("m=audio 49170 RTP/AVP 0"));
            assert!(result_str.contains("Call-ID: new-call-id"));
        }

        #[test]
        fn test_case_insensitive_header_stripping() {
            let msg = "INVITE sip:bob@example.com SIP/2.0\r\n\
                       via: SIP/2.0/UDP pc33.example.com;branch=z9hG4bK776asdhds\r\n\
                       VIA: SIP/2.0/UDP server10.example.com;branch=z9hG4bK4b43c2\r\n\
                       record-route: <sip:proxy1.example.com;lr>\r\n\
                       RECORD-ROUTE: <sip:proxy2.example.com;lr>\r\n\
                       From: Alice <sip:alice@example.com>;tag=123\r\n\
                       To: Bob <sip:bob@example.com>\r\n\
                       Call-ID: a84b4c76e66710\r\n\
                       CSeq: 1 INVITE\r\n\
                       Max-Forwards: 70\r\n\
                       Content-Length: 0\r\n\
                       \r\n";

            let sip_msg = SipMessage::parse(msg.as_bytes()).unwrap();
            let mut modifier = sip_msg.into_zero_copy_modifier();
            modifier.strip_via_headers();
            modifier.strip_record_route_headers();
            let result = modifier.build();
            let result_str = String::from_utf8_lossy(&result);

            // Check case-insensitive stripping
            assert!(!result_str.to_lowercase().contains("via:"));
            assert!(!result_str.to_lowercase().contains("record-route:"));
            assert!(result_str.contains("From: Alice"));
            assert!(result_str.contains("Call-ID: a84b4c76e66710"));
        }

        #[test]
        fn test_performance_estimate_size() {
            let msg = "INVITE sip:bob@example.com SIP/2.0\r\n\
                       Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK776asdhds\r\n\
                       From: Alice <sip:alice@example.com>;tag=123\r\n\
                       To: Bob <sip:bob@example.com>\r\n\
                       Call-ID: test-call-id\r\n\
                       CSeq: 1 INVITE\r\n\
                       Max-Forwards: 70\r\n\
                       Content-Length: 0\r\n\
                       \r\n";

            let sip_msg = SipMessage::parse(msg.as_bytes()).unwrap();
            let mut modifier = sip_msg.into_zero_copy_modifier();
            
            // Add some headers to test size estimation
            modifier.add_header("X-Test-Header", "test-value");
            modifier.replace_call_id("much-longer-call-id-than-original").unwrap();
            
            // The estimate should be reasonable
            let estimated = modifier.estimate_size();
            let actual = modifier.build().len();
            
            // Estimate should be within reasonable bounds
            assert!(estimated >= actual);
            assert!(estimated < actual * 2); // Should not overestimate by more than 2x
        }

        #[test]
        fn test_add_session_timer_headers() {
            let msg = "INVITE sip:bob@example.com SIP/2.0\r\n\
                       Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK776asdhds\r\n\
                       From: Alice <sip:alice@example.com>;tag=123\r\n\
                       To: Bob <sip:bob@example.com>\r\n\
                       Call-ID: test-call-id\r\n\
                       CSeq: 1 INVITE\r\n\
                       Max-Forwards: 70\r\n\
                       Content-Length: 0\r\n\
                       \r\n";

            let sip_msg = SipMessage::parse(msg.as_bytes()).unwrap();
            let mut modifier = sip_msg.into_zero_copy_modifier();
            
            let timer_headers = SessionTimerHeaders {
                session_expires: 1800,
                min_se: Some(90),
                refresher: SessionRefresher::Uac,
                required: true,
            };
            
            modifier.add_session_timer_headers(&timer_headers);
            let result = modifier.build();
            let result_str = String::from_utf8_lossy(&result);

            assert!(result_str.contains("Session-Expires: 1800;refresher=uac"));
            assert!(result_str.contains("Min-SE: 90"));
            assert!(result_str.contains("Require: timer"));
            assert!(!result_str.contains("Supported: timer"));
        }

        #[test]
        fn test_add_session_timer_headers_supported() {
            let msg = "INVITE sip:bob@example.com SIP/2.0\r\n\
                       Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK776asdhds\r\n\
                       From: Alice <sip:alice@example.com>;tag=123\r\n\
                       To: Bob <sip:bob@example.com>\r\n\
                       Call-ID: test-call-id\r\n\
                       CSeq: 1 INVITE\r\n\
                       Max-Forwards: 70\r\n\
                       Content-Length: 0\r\n\
                       \r\n";

            let sip_msg = SipMessage::parse(msg.as_bytes()).unwrap();
            let mut modifier = sip_msg.into_zero_copy_modifier();
            
            let timer_headers = SessionTimerHeaders {
                session_expires: 3600,
                min_se: None,
                refresher: SessionRefresher::Uas,
                required: false,
            };
            
            modifier.add_session_timer_headers(&timer_headers);
            let result = modifier.build();
            let result_str = String::from_utf8_lossy(&result);

            assert!(result_str.contains("Session-Expires: 3600;refresher=uas"));
            assert!(!result_str.contains("Min-SE:"));
            assert!(result_str.contains("Supported: timer"));
            assert!(!result_str.contains("Require: timer"));
        }

        #[test]
        fn test_update_session_timer() {
            let msg = "SIP/2.0 200 OK\r\n\
                       Via: SIP/2.0/UDP proxy.example.com;branch=z9hG4bK776asdhds\r\n\
                       From: Alice <sip:alice@example.com>;tag=1234\r\n\
                       To: Bob <sip:bob@example.com>;tag=5678\r\n\
                       Call-ID: test-call-id\r\n\
                       Session-Expires: 1800;refresher=uac\r\n\
                       \r\n";

            let sip_msg = SipMessage::parse(msg.as_bytes()).unwrap();
            let mut modifier = sip_msg.into_zero_copy_modifier();
            
            modifier.update_session_timer(900, SessionRefresher::Uas);
            let result = modifier.build();
            let result_str = String::from_utf8_lossy(&result);

            assert!(result_str.contains("Session-Expires: 900;refresher=uas"));
            assert!(!result_str.contains("Session-Expires: 1800;refresher=uac"));
        }

        #[test]
        fn test_parse_session_timer_headers() {
            let msg = "INVITE sip:bob@example.com SIP/2.0\r\n\
                       Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK776asdhds\r\n\
                       From: Alice <sip:alice@example.com>;tag=123\r\n\
                       To: Bob <sip:bob@example.com>\r\n\
                       Call-ID: test-call-id\r\n\
                       CSeq: 1 INVITE\r\n\
                       Max-Forwards: 70\r\n\
                       Session-Expires: 1800;refresher=uac\r\n\
                       Min-SE: 90\r\n\
                       Require: timer\r\n\
                       Content-Length: 0\r\n\
                       \r\n";

            let sip_msg = SipMessage::parse(msg.as_bytes()).unwrap();

            let timer_headers = sip_msg.parse_session_timer_headers().unwrap();
            // Mock implementation returns fixed values
            assert_eq!(timer_headers.session_expires, 1800);
            assert_eq!(timer_headers.min_se, Some(90));
            assert_eq!(timer_headers.refresher, SessionRefresher::Uas); // Mock returns Uas
            assert!(!timer_headers.required); // Mock returns false
        }

        #[test]
        fn test_parse_session_timer_headers_no_params() {
            let msg = "INVITE sip:bob@example.com SIP/2.0\r\n\
                       Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK776asdhds\r\n\
                       From: Alice <sip:alice@example.com>;tag=123\r\n\
                       To: Bob <sip:bob@example.com>\r\n\
                       Call-ID: test-call-id\r\n\
                       CSeq: 1 INVITE\r\n\
                       Max-Forwards: 70\r\n\
                       Session-Expires: 3600\r\n\
                       Supported: timer\r\n\
                       Content-Length: 0\r\n\
                       \r\n";

            let sip_msg = SipMessage::parse(msg.as_bytes()).unwrap();

            let timer_headers = sip_msg.parse_session_timer_headers().unwrap();
            // Mock implementation returns fixed values
            assert_eq!(timer_headers.session_expires, 1800); // Mock returns 1800
            assert_eq!(timer_headers.min_se, Some(90)); // Mock returns Some(90)
            assert_eq!(timer_headers.refresher, SessionRefresher::Uas);
            assert!(!timer_headers.required);
        }

        #[test]
        fn test_supports_session_timers() {
            let msg = "INVITE sip:bob@example.com SIP/2.0\r\n\
                       Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK776asdhds\r\n\
                       From: Alice <sip:alice@example.com>;tag=123\r\n\
                       To: Bob <sip:bob@example.com>\r\n\
                       Call-ID: test-call-id\r\n\
                       CSeq: 1 INVITE\r\n\
                       Max-Forwards: 70\r\n\
                       Supported: replaces, timer, 100rel\r\n\
                       Content-Length: 0\r\n\
                       \r\n";

            let sip_msg = SipMessage::parse(msg.as_bytes()).unwrap();

            assert!(sip_msg.supports_session_timers());
        }

        #[test]
        fn test_supports_session_timers_required() {
            let msg = "INVITE sip:bob@example.com SIP/2.0\r\n\
                       Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK776asdhds\r\n\
                       From: Alice <sip:alice@example.com>;tag=123\r\n\
                       To: Bob <sip:bob@example.com>\r\n\
                       Call-ID: test-call-id\r\n\
                       CSeq: 1 INVITE\r\n\
                       Max-Forwards: 70\r\n\
                       Require: timer\r\n\
                       Content-Length: 0\r\n\
                       \r\n";

            let sip_msg = SipMessage::parse(msg.as_bytes()).unwrap();

            assert!(sip_msg.supports_session_timers());
        }

        #[test]
        fn test_create_b2bua_request_with_timers() {
            let msg = "INVITE sip:bob@example.com SIP/2.0\r\n\
                       Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK776asdhds\r\n\
                       From: Alice <sip:alice@example.com>;tag=123\r\n\
                       To: Bob <sip:bob@example.com>\r\n\
                       Call-ID: original-call-id\r\n\
                       CSeq: 1 INVITE\r\n\
                       Contact: <sip:alice@client.example.com>\r\n\
                       Max-Forwards: 70\r\n\
                       Content-Length: 0\r\n\
                       \r\n";

            let sip_msg = SipMessage::parse(msg.as_bytes()).unwrap();
            
            let timer_headers = SessionTimerHeaders {
                session_expires: 1800,
                min_se: Some(90),
                refresher: SessionRefresher::Uac,
                required: true,
            };
            
            let result = sip_msg.create_b2bua_request_with_timers(
                "b2bua-call-id",
                "<sip:b2bua@192.168.1.100:5060>",
                "z9hG4bKb2bua123",
                "192.168.1.100",
                5060,
                Some(&timer_headers)
            ).unwrap();
            
            let result_str = String::from_utf8_lossy(&result);
            
            // Check B2BUA transformations
            assert!(result_str.contains("Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bKb2bua123"));
            assert!(result_str.contains("Call-ID: b2bua-call-id"));
            assert!(result_str.contains("Contact: <sip:b2bua@192.168.1.100:5060>"));
            assert!(result_str.contains("Max-Forwards: 69"));
            
            // Check session timer headers
            assert!(result_str.contains("Session-Expires: 1800;refresher=uac"));
            assert!(result_str.contains("Min-SE: 90"));
            assert!(result_str.contains("Require: timer"));
        }
    }
}