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
pub mod zero_copy;
pub mod sdp;
pub mod error;
pub mod b2bua;
pub mod pool;
pub mod limits;
pub mod validation;

// Re-export core types and functionality
pub use types::*;
// pub use parsing::*; // Only contains macros now, which are re-exported via main_impl
pub use headers::*;
pub use modification::*;
pub use benchmark::*;
pub use zero_copy::*;
pub use sdp::*;
pub use error::*;
pub use b2bua::*;
pub use pool::*;
pub use limits::*;
pub use validation::*;

// Legacy compatibility - continue to export from main_impl for any remaining functionality
pub use main_impl::*;