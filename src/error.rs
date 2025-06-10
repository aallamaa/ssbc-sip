//! Simplified error handling for SSBC
//! 
//! Unified error system that consolidates all error types into a simple, 
//! easy-to-use interface suitable for high-performance SIP parsing.

use std::fmt;
use std::error::Error as StdError;

/// Simplified unified error type for SSBC operations
#[derive(Debug, Clone, PartialEq)]
pub enum SsbcError {
    /// Parsing errors (SIP message, headers, SDP, etc.)
    ParseError {
        message: String,
        position: Option<(usize, usize)>, // (line, column)
        context: Option<String>,
    },
    
    /// Network and transport errors
    TransportError {
        endpoint: String,
        reason: String,
        recoverable: bool,
    },
    
    /// Resource exhaustion and limits
    ResourceError {
        resource_type: ResourceType,
        current_usage: u64,
        limit: u64,
    },
    
    /// B2BUA state and operation errors
    StateError {
        operation: String,
        reason: String,
        context: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum ResourceType {
    Memory,
    ConcurrentCalls,
    Bandwidth,
    Connections,
}

impl fmt::Display for SsbcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SsbcError::ParseError { message, position, context } => {
                write!(f, "Parse error: {}", message)?;
                if let Some((line, col)) = position {
                    write!(f, " at {}:{}", line, col)?;
                }
                if let Some(ctx) = context {
                    write!(f, " ({})", ctx)?;
                }
                Ok(())
            },
            SsbcError::TransportError { endpoint, reason, recoverable } => {
                write!(f, "Transport error to {}: {} (recoverable: {})", endpoint, reason, recoverable)
            },
            SsbcError::ResourceError { resource_type, current_usage, limit } => {
                write!(f, "Resource exhaustion: {:?} usage {} exceeds limit {}", 
                       resource_type, current_usage, limit)
            },
            SsbcError::StateError { operation, reason, context } => {
                write!(f, "State error: {} failed - {}", operation, reason)?;
                if let Some(ctx) = context {
                    write!(f, " ({})", ctx)?;
                }
                Ok(())
            },
        }
    }
}

impl StdError for SsbcError {}

impl SsbcError {
    /// Create a parse error with optional position
    pub fn parse_error(message: impl Into<String>, position: Option<(usize, usize)>, context: Option<String>) -> Self {
        SsbcError::ParseError {
            message: message.into(),
            position,
            context,
        }
    }

    /// Create a transport error
    pub fn transport_error(endpoint: impl Into<String>, reason: impl Into<String>, recoverable: bool) -> Self {
        SsbcError::TransportError {
            endpoint: endpoint.into(),
            reason: reason.into(),
            recoverable,
        }
    }

    /// Create a resource exhaustion error
    pub fn resource_error(resource_type: ResourceType, current: u64, limit: u64) -> Self {
        SsbcError::ResourceError {
            resource_type,
            current_usage: current,
            limit,
        }
    }

    /// Create a state error
    pub fn state_error(operation: impl Into<String>, reason: impl Into<String>, context: Option<String>) -> Self {
        SsbcError::StateError {
            operation: operation.into(),
            reason: reason.into(),
            context,
        }
    }

    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            SsbcError::ParseError { .. } => true,
            SsbcError::TransportError { recoverable, .. } => *recoverable,
            SsbcError::ResourceError { .. } => true,
            SsbcError::StateError { .. } => false,
        }
    }

    /// Get error category for metrics
    pub fn category(&self) -> &'static str {
        match self {
            SsbcError::ParseError { .. } => "parsing",
            SsbcError::TransportError { .. } => "transport",
            SsbcError::ResourceError { .. } => "resource",
            SsbcError::StateError { .. } => "state",
        }
    }
}

/// Result type for SSBC operations
pub type SsbcResult<T> = Result<T, SsbcError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let parse_error = SsbcError::parse_error("Invalid header", Some((10, 5)), None);
        assert!(parse_error.to_string().contains("Parse error"));
        assert!(parse_error.to_string().contains("10:5"));
        
        let transport_error = SsbcError::transport_error("192.168.1.1:5060", "Connection refused", true);
        assert!(transport_error.is_recoverable());
    }

    #[test]
    fn test_error_categories() {
        let parse_error = SsbcError::parse_error("test", None, None);
        assert_eq!(parse_error.category(), "parsing");
        
        let resource_error = SsbcError::resource_error(ResourceType::Memory, 100, 50);
        assert_eq!(resource_error.category(), "resource");
    }
}