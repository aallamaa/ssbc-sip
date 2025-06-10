//! Input validation utilities for security
//! 
//! Provides validation functions to prevent injection attacks and ensure data integrity

use crate::error::{SsbcError, SsbcResult};

/// Validate UTF-8 string and check for dangerous characters
pub fn validate_display_name(name: &str) -> SsbcResult<()> {
    // Check valid UTF-8 (Rust strings are always valid UTF-8)
    // But we need to check for control characters
    for ch in name.chars() {
        match ch {
            // Disallow control characters except tab
            '\0'..='\x08' | '\x0B'..='\x1F' | '\x7F' => {
                return Err(SsbcError::ParseError {
                    message: format!("Invalid control character in display name: {:?}", ch),
                    position: None,
                    context: Some("Security validation".to_string()),
                });
            }
            // Disallow line breaks in display names
            '\r' | '\n' => {
                return Err(SsbcError::ParseError {
                    message: "Line breaks not allowed in display name".to_string(),
                    position: None,
                    context: Some("Security validation".to_string()),
                });
            }
            _ => {}
        }
    }
    Ok(())
}

/// Validate header field value for injection attacks
pub fn validate_header_value(value: &str) -> SsbcResult<()> {
    // Check for CRLF injection
    if value.contains('\r') || value.contains('\n') {
        return Err(SsbcError::ParseError {
            message: "CRLF injection attempt detected in header value".to_string(),
            position: None,
            context: Some("Security validation".to_string()),
        });
    }
    
    // Check for null bytes
    if value.contains('\0') {
        return Err(SsbcError::ParseError {
            message: "Null byte in header value".to_string(),
            position: None,
            context: Some("Security validation".to_string()),
        });
    }
    
    Ok(())
}

/// Validate numeric header values
pub fn validate_numeric_header(name: &str, value: &str, min: Option<u32>, max: Option<u32>) -> SsbcResult<u32> {
    let num = value.trim().parse::<u32>().map_err(|_| {
        SsbcError::ParseError {
            message: format!("{} must be numeric: {}", name, value),
            position: None,
            context: None,
        }
    })?;
    
    if let Some(min_val) = min {
        if num < min_val {
            return Err(SsbcError::ParseError {
                message: format!("{} value {} is below minimum {}", name, num, min_val),
                position: None,
                context: None,
            });
        }
    }
    
    if let Some(max_val) = max {
        if num > max_val {
            return Err(SsbcError::ParseError {
                message: format!("{} value {} exceeds maximum {}", name, num, max_val),
                position: None,
                context: None,
            });
        }
    }
    
    Ok(num)
}

/// Validate Content-Length header
pub fn validate_content_length(value: &str, actual_body_length: usize) -> SsbcResult<usize> {
    let declared_length = validate_numeric_header("Content-Length", value, Some(0), None)? as usize;
    
    if declared_length != actual_body_length {
        return Err(SsbcError::ParseError {
            message: format!(
                "Content-Length mismatch: declared {} but body is {} bytes", 
                declared_length, actual_body_length
            ),
            position: None,
            context: Some("Security validation".to_string()),
        });
    }
    
    Ok(declared_length)
}