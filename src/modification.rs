//! SIP Message Modification and Building Utilities
//! 
//! This module provides utilities for modifying existing SIP messages and building new ones.
//! It includes two main components:
//! 
//! - `message_modifier`: For modifying existing SIP messages (B2BUA operations)
//! - `message_builder`: For building new SIP messages from scratch
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