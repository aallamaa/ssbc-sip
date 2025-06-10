//! Common types and enums used throughout the SSBC library

use std::collections::HashMap;
use std::fmt;
use strum_macros::{Display, EnumString};

/// SIP URI schemes as defined in RFC 3261
#[derive(Debug, Clone, PartialEq, Eq, Display, EnumString, Default)]
pub enum Scheme {
    #[default]
    #[strum(serialize = "sip")]
    SIP,
    #[strum(serialize = "sips")]
    SIPS,
    #[strum(serialize = "tel")]
    TEL,
}

/// SIP methods as defined in RFC 3261 and extensions
#[derive(Debug, Clone, PartialEq, Eq, Hash, Display, EnumString)]
pub enum Method {
    INVITE,
    ACK,
    OPTIONS,
    BYE,
    CANCEL,
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

/// Represents a range of text within a message for zero-copy parsing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TextRange {
    pub start: u16,
    pub end: u16,
}

impl TextRange {
    /// Create a new TextRange
    pub fn new(start: u16, end: u16) -> Self {
        TextRange { start, end }
    }

    /// Create a TextRange from usize values
    pub fn from_usize(start: usize, end: usize) -> Self {
        TextRange {
            start: start as u16,
            end: end as u16,
        }
    }

    /// Get the string slice this range represents
    pub fn as_str<'a>(&self, text: &'a str) -> &'a str {
        &text[self.start as usize..self.end as usize]
    }

    /// Get the length of this range
    pub fn len(&self) -> usize {
        (self.end - self.start) as usize
    }

    /// Check if this range is empty
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

/// Parameter key type for efficient parameter storage
pub type ParamKey = TextRange;

/// Parameter value type (optional for flags)
pub type ParamValue = Option<TextRange>;

/// Parameter map type for storing header parameters
pub type ParamMap = HashMap<ParamKey, ParamValue>;

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

impl fmt::Display for SipUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // For Display implementation, we need a simplified version
        // that doesn't require access to the original message
        // This is a basic implementation - in a real scenario you'd want
        // to store the original URI string or provide a reference to the message
        write!(f, "{}:", self.scheme)?;
        if let Some(port) = self.port {
            write!(f, "host:{}", port)?;
        } else {
            write!(f, "host")?;
        }
        Ok(())
    }
}

/// Represents a SIP address, used in headers like To, From, etc.
#[derive(Debug, Clone, PartialEq)]
pub struct Address {
    /// The full address text range
    pub full_range: TextRange,
    pub display_name: Option<TextRange>,
    pub uri: SipUri,
    pub params: ParamMap,
}

/// Represents a Via header
#[derive(Debug, Clone, PartialEq)]
pub struct Via {
    /// The full Via header text range
    pub full_range: TextRange,
    pub sent_protocol: TextRange,
    pub sent_by: TextRange,
    pub params: ParamMap,
}

/// Event package enumeration for SUBSCRIBE/NOTIFY
#[derive(Debug, Clone, PartialEq, Eq, Hash, Display, EnumString)]
pub enum EventPackage {
    #[strum(serialize = "presence")]
    Presence,
    #[strum(serialize = "dialog")]
    Dialog,
    #[strum(serialize = "message-summary")]
    MessageSummary,
    #[strum(serialize = "reg")]
    Registration,
    #[strum(serialize = "refer")]
    Refer,
    #[strum(serialize = "call-info")]
    CallInfo,
    #[strum(serialize = "line-seize")]
    LineSeize,
    #[strum(serialize = "kpml")]
    KPML,
    #[strum(serialize = "conference")]
    Conference,
    #[strum(serialize = "presence.winfo")]
    PresenceWinfo,
    #[strum(serialize = "dialog.winfo")]
    DialogWinfo,
}

/// Represents a parsed event package with parameters for parsing
#[derive(Debug, Clone, PartialEq)]
pub struct EventPackageData {
    pub event_type: TextRange,
    pub event_params: ParamMap,
}

/// Header value types for parsed headers
#[derive(Debug, Clone, PartialEq)]
pub enum HeaderValue {
    Raw(TextRange),
    Address(Address),
    Via(Via),
}

// ParseError removed - now using unified SsbcError from error.rs module

/// Utility methods for TextRange with string operations
impl TextRange {
    /// Get parameter key string from raw message
    pub fn get_param_key<'a>(&self, raw_message: &'a str) -> &'a str {
        self.as_str(raw_message)
    }

    /// Get parameter value string from raw message  
    pub fn get_param_value<'a>(&self, raw_message: &'a str) -> Option<&'a str> {
        Some(self.as_str(raw_message))
    }
}

/// Helper trait for parameter maps to work with raw message strings
pub trait ParamMapUtils {
    fn get_param_key<'a>(&self, raw_message: &'a str) -> &'a str;
    fn get_param_value<'a>(&self, raw_message: &'a str) -> Option<&'a str>;
}

impl ParamMapUtils for ParamKey {
    fn get_param_key<'a>(&self, raw_message: &'a str) -> &'a str {
        self.as_str(raw_message)
    }

    fn get_param_value<'a>(&self, raw_message: &'a str) -> Option<&'a str> {
        Some(self.as_str(raw_message))
    }
}

impl ParamMapUtils for &ParamValue {
    fn get_param_key<'a>(&self, _raw_message: &'a str) -> &'a str {
        ""
    }

    fn get_param_value<'a>(&self, raw_message: &'a str) -> Option<&'a str> {
        self.as_ref().map(|range| range.as_str(raw_message))
    }
}