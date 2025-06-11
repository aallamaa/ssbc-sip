// Input validation and sanitization for SIP messages

use crate::error::{SsbcError, SsbcResult};
use crate::types::TextRange;

/// Validate that a string contains only valid UTF-8 characters
pub fn validate_utf8(_input: &str) -> SsbcResult<()> {
    // Rust strings are already guaranteed to be valid UTF-8
    // This function is here for explicit validation and future extensions
    Ok(())
}

/// Validate and sanitize a header value
pub fn sanitize_header_value(value: &str) -> SsbcResult<String> {
    // First check for header injection attempts (CRLF) before sanitizing
    if value.contains("\r\n") || value.contains("\n") || value.contains("\r") {
        return Err(SsbcError::ParseError {
            message: "Header injection attempt detected".to_string(),
            position: None,
            context: Some("Header value contains CRLF".to_string()),
        });
    }
    
    // Remove any control characters except tab
    let sanitized: String = value
        .chars()
        .filter(|&c| c == '\t' || !c.is_control())
        .collect();
    
    Ok(sanitized)
}

/// Validate a SIP URI for security issues
pub fn validate_uri(uri: &str, max_depth: usize) -> SsbcResult<()> {
    // Check for null bytes
    if uri.contains('\0') {
        return Err(SsbcError::ParseError {
            message: "URI contains null bytes".to_string(),
            position: None,
            context: None,
        });
    }
    
    // Check for excessive nesting/recursion (simplified check)
    let depth = uri.matches('<').count();
    if depth > max_depth {
        return Err(SsbcError::ParseError {
            message: format!("URI depth {} exceeds maximum {}", depth, max_depth),
            position: None,
            context: None,
        });
    }
    
    // Check for suspicious patterns
    let suspicious_patterns = [
        "../",  // Directory traversal
        "..\\", // Windows directory traversal
        "%00",  // Null byte encoding
        "%0d",  // CR encoding
        "%0a",  // LF encoding
    ];
    
    for pattern in &suspicious_patterns {
        if uri.contains(pattern) {
            return Err(SsbcError::ParseError {
                message: format!("URI contains suspicious pattern: {}", pattern),
                position: None,
                context: None,
            });
        }
    }
    
    Ok(())
}

/// Validate a header name
pub fn validate_header_name(name: &str) -> SsbcResult<()> {
    // Header names should only contain token characters
    // token = 1*<any CHAR except CTLs or separators>
    for ch in name.chars() {
        if ch.is_control() || 
           ch == '(' || ch == ')' || ch == '<' || ch == '>' || 
           ch == '@' || ch == ',' || ch == ';' || ch == ':' || 
           ch == '\\' || ch == '"' || ch == '/' || ch == '[' || 
           ch == ']' || ch == '?' || ch == '=' || ch == '{' || 
           ch == '}' || ch == ' ' || ch == '\t' {
            return Err(SsbcError::ParseError {
                message: format!("Invalid character '{}' in header name", ch),
                position: None,
                context: Some(name.to_string()),
            });
        }
    }
    
    Ok(())
}

/// Validate a method name
pub fn validate_method(method: &str) -> SsbcResult<()> {
    // Method should only contain uppercase letters
    for ch in method.chars() {
        if !ch.is_ascii_uppercase() {
            return Err(SsbcError::ParseError {
                message: format!("Invalid character '{}' in method name", ch),
                position: None,
                context: Some(method.to_string()),
            });
        }
    }
    
    // Check reasonable length
    if method.is_empty() || method.len() > 32 {
        return Err(SsbcError::ParseError {
            message: "Method name has invalid length".to_string(),
            position: None,
            context: Some(format!("Length: {}", method.len())),
        });
    }
    
    Ok(())
}

/// Validate SIP version string
pub fn validate_sip_version(version: &str) -> SsbcResult<()> {
    // Should be exactly "SIP/2.0"
    if version != "SIP/2.0" {
        return Err(SsbcError::ParseError {
            message: format!("Unsupported SIP version: {}", version),
            position: None,
            context: None,
        });
    }
    
    Ok(())
}

/// Validate a status code
pub fn validate_status_code(code: u16) -> SsbcResult<()> {
    // Status codes should be 100-699
    if code < 100 || code > 699 {
        return Err(SsbcError::ParseError {
            message: format!("Invalid status code: {}", code),
            position: None,
            context: None,
        });
    }
    
    Ok(())
}

/// Validate that a string slice is within message bounds
pub fn validate_range(range: &TextRange, message_len: usize) -> SsbcResult<()> {
    if range.start > message_len || range.end > message_len {
        return Err(SsbcError::ParseError {
            message: "Text range exceeds message bounds".to_string(),
            position: None,
            context: Some(format!("Range: {}..{}, Message length: {}", 
                range.start, range.end, message_len)),
        });
    }
    
    if range.start > range.end {
        return Err(SsbcError::ParseError {
            message: "Invalid text range (start > end)".to_string(),
            position: None,
            context: Some(format!("Range: {}..{}", range.start, range.end)),
        });
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_sanitize_header_value() {
        // Normal header value
        assert_eq!(
            sanitize_header_value("normal value").unwrap(),
            "normal value"
        );
        
        // With tab (allowed)
        assert_eq!(
            sanitize_header_value("value\twith\ttab").unwrap(),
            "value\twith\ttab"
        );
        
        // Control characters removed
        assert_eq!(
            sanitize_header_value("value\x00with\x01control").unwrap(),
            "valuewithcontrol"
        );
        
        // Header injection attempt
        assert!(sanitize_header_value("value\r\nInjected: header").is_err());
    }
    
    #[test]
    fn test_validate_uri() {
        // Valid URIs
        assert!(validate_uri("sip:user@example.com", 10).is_ok());
        assert!(validate_uri("sips:user@example.com:5061", 10).is_ok());
        
        // Null byte
        assert!(validate_uri("sip:user\0@example.com", 10).is_err());
        
        // Directory traversal
        assert!(validate_uri("sip:../../../etc/passwd@example.com", 10).is_err());
        
        // Excessive depth
        assert!(validate_uri("sip:<<<<<<<<<nested>>>>>>>>>@example.com", 5).is_err());
    }
    
    #[test]
    fn test_validate_header_name() {
        // Valid names
        assert!(validate_header_name("Content-Type").is_ok());
        assert!(validate_header_name("X-Custom-Header").is_ok());
        
        // Invalid characters
        assert!(validate_header_name("Content Type").is_err()); // Space
        assert!(validate_header_name("Content:Type").is_err()); // Colon
        assert!(validate_header_name("Content\tType").is_err()); // Tab
    }
    
    #[test]
    fn test_validate_method() {
        // Valid methods
        assert!(validate_method("INVITE").is_ok());
        assert!(validate_method("REGISTER").is_ok());
        
        // Invalid methods
        assert!(validate_method("invite").is_err()); // Lowercase
        assert!(validate_method("IN VITE").is_err()); // Space
        assert!(validate_method("").is_err()); // Empty
        assert!(validate_method("A".repeat(33).as_str()).is_err()); // Too long
    }
}