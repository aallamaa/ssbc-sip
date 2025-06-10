//! SIP message parsing functionality
//! 
//! This module contains the core parsing logic for SIP messages, including
//! lazy parsing capabilities optimized for zero-copy parsing.

// Module contains only macro definitions, no direct type usage

/// Macro to validate a required Option-type header
#[macro_export]
macro_rules! validate_required_option_header {
    ($self:expr, $header:expr, $header_name:expr) => {
        if $header.is_none() {
            return Err(SsbcError::ParseError {
                message: format!("Missing required {} header", $header_name),
                position: None,
                context: None,
            });
        }
    };
}

/// Macro to validate a required Vec-type header
#[macro_export]
macro_rules! validate_required_vec_header {
    ($self:expr, $headers:expr, $header_name:expr) => {
        if $headers.is_empty() {
            return Err(SsbcError::ParseError {
                message: format!("Missing required {} header", $header_name),
                position: None,
                context: None,
            });
        }
    };
}

/// Macro to check for duplicate headers and set header value
#[macro_export]
macro_rules! check_duplicate_and_set {
    ($self:expr, $header_field:expr, $value_range:expr, $header_name:expr, $range:expr) => {{
        // Check for duplicate header
        if $header_field.is_some() {
            return Err(SsbcError::ParseError {
                message: format!("Duplicate {} header", $header_name),
                position: None,
                context: None,
            });
        }
        $header_field = Some(HeaderValue::Raw($value_range));
    }};
}