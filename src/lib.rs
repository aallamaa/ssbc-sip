//! SSBC - SIP Stack for Session Border Controllers
//! 
//! This library provides a high-performance SIP parser with lazy parsing capabilities,
//! optimized for B2BUA (Back-to-Back User Agent) mode.

mod benchmark;
mod main_impl;
pub mod modification;
pub mod parsing;
pub mod headers;
pub mod types;

// Re-export core types and functionality
pub use types::*;
// pub use parsing::*; // Only contains macros now, which are re-exported via main_impl
pub use headers::*;
pub use modification::*;
pub use benchmark::*;

// Legacy compatibility - continue to export from main_impl for any remaining functionality
pub use main_impl::*;