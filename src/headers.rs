//! SIP header extraction and manipulation utilities
//! 
//! This module provides utilities for working with SIP headers, including
//! extraction of header values and parameters with support for RFC 3261
//! compact forms.

use crate::main_impl::SipMessage;

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