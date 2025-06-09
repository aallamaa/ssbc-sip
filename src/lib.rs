//! SSBC - SIP Stack for Session Border Controllers
//! 
//! This library provides a high-performance SIP parser with lazy parsing capabilities,
//! optimized for B2BUA (Back-to-Back User Agent) mode.

mod benchmark;
mod main_impl;

pub use main_impl::*;
pub use benchmark::*;