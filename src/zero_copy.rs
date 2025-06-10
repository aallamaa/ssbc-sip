//! Zero-copy parsing optimizations for SIP messages
//! 
//! This module provides optimized parsing that minimizes allocations
//! by using string slices and borrowed data where possible.

use std::str;

/// Zero-copy SIP message parser that uses string slices instead of owned strings
/// to minimize memory allocations during parsing
pub struct ZeroCopySipMessage<'a> {
    raw_message: &'a str,
    start_line: Option<&'a str>,
    headers: Vec<(&'a str, &'a str)>, // (header_name, header_value)
    body: Option<&'a str>,
    parsed: bool,
}

impl<'a> ZeroCopySipMessage<'a> {
    /// Create a new zero-copy SIP message from a string slice
    pub fn new(message: &'a str) -> Self {
        Self {
            raw_message: message,
            start_line: None,
            headers: Vec::new(),
            body: None,
            parsed: false,
        }
    }

    /// Parse the SIP message using zero-copy techniques
    pub fn parse(&mut self) -> Result<(), &'static str> {
        if self.parsed {
            return Ok(());
        }

        let lines: Vec<&str> = self.raw_message.lines().collect();
        if lines.is_empty() {
            return Err("Empty message");
        }

        // Parse start line
        self.start_line = Some(lines[0]);

        // Find the empty line that separates headers from body
        let mut body_start_idx = None;
        for (idx, line) in lines.iter().enumerate().skip(1) {
            if line.trim().is_empty() {
                body_start_idx = Some(idx + 1);
                break;
            }
        }

        // Parse headers (between start line and empty line)
        let header_end = body_start_idx.unwrap_or(lines.len());
        self.headers.reserve(header_end - 1);
        
        for line in &lines[1..header_end] {
            if let Some(colon_pos) = line.find(':') {
                let name = line[..colon_pos].trim();
                let value = line[colon_pos + 1..].trim();
                self.headers.push((name, value));
            }
        }

        // Parse body if present
        if let Some(body_idx) = body_start_idx {
            if body_idx < lines.len() {
                let body_lines = &lines[body_idx..];
                if !body_lines.is_empty() {
                    // Find the start of body in the original string
                    let body_start = self.raw_message
                        .lines()
                        .take(body_idx)
                        .map(|line| line.len() + 1) // +1 for newline
                        .sum::<usize>();
                    
                    if body_start < self.raw_message.len() {
                        self.body = Some(&self.raw_message[body_start..]);
                    }
                }
            }
        }

        self.parsed = true;
        Ok(())
    }

    /// Get the start line (request line or status line)
    pub fn start_line(&self) -> Option<&'a str> {
        self.start_line
    }

    /// Get all headers as (name, value) pairs
    pub fn headers(&self) -> &[(&'a str, &'a str)] {
        &self.headers
    }

    /// Get a specific header value by name (case-insensitive)
    pub fn get_header(&self, name: &str) -> Option<&'a str> {
        self.headers
            .iter()
            .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
            .map(|(_, value)| *value)
    }

    /// Get all header values for a given name (case-insensitive)
    pub fn get_headers(&self, name: &str) -> Vec<&'a str> {
        self.headers
            .iter()
            .filter(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
            .map(|(_, value)| *value)
            .collect()
    }

    /// Get the message body
    pub fn body(&self) -> Option<&'a str> {
        self.body
    }

    /// Check if this is a request message
    pub fn is_request(&self) -> bool {
        self.start_line
            .map(|line| !line.starts_with("SIP/2.0"))
            .unwrap_or(false)
    }

    /// Extract method from request line or None if this is a response
    pub fn method(&self) -> Option<&'a str> {
        if !self.is_request() {
            return None;
        }
        
        self.start_line
            .and_then(|line| line.split_whitespace().next())
    }

    /// Extract status code from response line or None if this is a request
    pub fn status_code(&self) -> Option<u16> {
        if self.is_request() {
            return None;
        }

        self.start_line
            .and_then(|line| {
                let mut parts = line.split_whitespace();
                parts.next(); // Skip "SIP/2.0"
                parts.next()?.parse().ok()
            })
    }

    /// Extract Call-ID header
    pub fn call_id(&self) -> Option<&'a str> {
        self.get_header("Call-ID")
    }

    /// Extract From header
    pub fn from_header(&self) -> Option<&'a str> {
        self.get_header("From")
    }

    /// Extract To header  
    pub fn to_header(&self) -> Option<&'a str> {
        self.get_header("To")
    }

    /// Extract Via headers
    pub fn via_headers(&self) -> Vec<&'a str> {
        self.get_headers("Via")
    }

    /// Extract Contact headers
    pub fn contact_headers(&self) -> Vec<&'a str> {
        self.get_headers("Contact")
    }

    /// Extract CSeq header
    pub fn cseq(&self) -> Option<&'a str> {
        self.get_header("CSeq")
    }

    /// Get the raw message
    pub fn raw_message(&self) -> &'a str {
        self.raw_message
    }
}

/// Fast E.164 number extraction using zero-copy techniques
pub fn extract_e164_fast(uri: &str) -> Option<&str> {
    // Find the + character
    let plus_pos = uri.find('+')?;
    let after_plus = &uri[plus_pos + 1..];
    
    // Find the end of the number (first non-digit)
    let end_pos = after_plus
        .char_indices()
        .find(|(_, c)| !c.is_ascii_digit())
        .map(|(idx, _)| idx)
        .unwrap_or(after_plus.len());
    
    if end_pos > 0 {
        Some(&uri[plus_pos..plus_pos + 1 + end_pos])
    } else {
        None
    }
}

/// Fast trunk group extraction using zero-copy techniques
pub fn extract_trunk_group_fast(contact: &str) -> Option<&str> {
    // Look for "tgrp=" (case insensitive)
    let tgrp_start = contact.to_lowercase().find("tgrp=")?;
    let value_start = tgrp_start + 5; // Length of "tgrp="
    
    if value_start >= contact.len() {
        return None;
    }
    
    let value_part = &contact[value_start..];
    
    // Find the end of the trunk group value (first delimiter)
    let end_pos = value_part
        .char_indices()
        .find(|(_, c)| matches!(c, ';' | '@' | '>' | ' ' | '\t'))
        .map(|(idx, _)| idx)
        .unwrap_or(value_part.len());
    
    if end_pos > 0 {
        Some(&value_part[..end_pos])
    } else {
        None
    }
}

/// Header name interning to reduce string allocations
/// Common SIP headers are pre-allocated as static strings
pub mod header_names {
    pub const VIA: &str = "Via";
    pub const FROM: &str = "From";
    pub const TO: &str = "To";
    pub const CALL_ID: &str = "Call-ID";
    pub const CSEQ: &str = "CSeq";
    pub const CONTACT: &str = "Contact";
    pub const CONTENT_LENGTH: &str = "Content-Length";
    pub const CONTENT_TYPE: &str = "Content-Type";
    pub const MAX_FORWARDS: &str = "Max-Forwards";
    pub const USER_AGENT: &str = "User-Agent";
    pub const ALLOW: &str = "Allow";
    pub const SUPPORTED: &str = "Supported";
    pub const REQUIRE: &str = "Require";
    pub const ROUTE: &str = "Route";
    pub const RECORD_ROUTE: &str = "Record-Route";
    pub const AUTHORIZATION: &str = "Authorization";
    pub const WWW_AUTHENTICATE: &str = "WWW-Authenticate";
    pub const P_ASSERTED_IDENTITY: &str = "P-Asserted-Identity";
    pub const SESSION_EXPIRES: &str = "Session-Expires";
    pub const MIN_SE: &str = "Min-SE";
    pub const RACK: &str = "RAck";
    pub const RSEQ: &str = "RSeq";
    pub const REASON: &str = "Reason";
    pub const SERVER: &str = "Server";
    pub const WARNING: &str = "Warning";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_copy_parsing() {
        let message = "INVITE sip:user@example.com SIP/2.0\r\nFrom: <sip:caller@example.com>;tag=123\r\nTo: <sip:user@example.com>\r\nCall-ID: test-call-id\r\nCSeq: 1 INVITE\r\nVia: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK123\r\nContent-Length: 0\r\n\r\n";
        
        let mut msg = ZeroCopySipMessage::new(message);
        assert!(msg.parse().is_ok());
        
        assert!(msg.is_request());
        assert_eq!(msg.method(), Some("INVITE"));
        assert_eq!(msg.call_id(), Some("test-call-id"));
        assert_eq!(msg.from_header(), Some("<sip:caller@example.com>;tag=123"));
        assert_eq!(msg.via_headers().len(), 1);
    }

    #[test]
    fn test_fast_e164_extraction() {
        assert_eq!(extract_e164_fast("sip:+2693347248@host"), Some("+2693347248"));
        assert_eq!(extract_e164_fast("tel:+14073982735"), Some("+14073982735"));
        assert_eq!(extract_e164_fast("sip:+44126439501@host;user=phone"), Some("+44126439501"));
        assert_eq!(extract_e164_fast("sip:user@host"), None);
    }

    #[test] 
    fn test_fast_trunk_group_extraction() {
        assert_eq!(
            extract_trunk_group_fast("sip:user;tgrp=ETISALAT@host"), 
            Some("ETISALAT")
        );
        assert_eq!(
            extract_trunk_group_fast("sip:user;tgrp=CTHuaweiCore3CLI*4;other=param@host"),
            Some("CTHuaweiCore3CLI*4")
        );
        assert_eq!(extract_trunk_group_fast("sip:user@host"), None);
    }
}