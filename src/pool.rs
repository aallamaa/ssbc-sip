//! Simplified SIP Message Pooling for High-Performance Allocation Management
//! 
//! Provides basic object pooling for SipMessage to reduce allocation overhead.
//! Focused on core functionality without excessive statistics tracking.

use crate::{SipMessage, error::SsbcResult, error::SsbcError};
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;

/// Simple pool configuration
#[derive(Debug, Clone, Copy)]
pub struct PoolConfig {
    /// Initial pool size
    pub initial_size: usize,
    /// Maximum pool size (0 = unlimited)
    pub max_size: usize,
    /// Whether to pre-allocate initial objects
    pub pre_allocate: bool,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            initial_size: 50,
            max_size: 200,
            pre_allocate: true,
        }
    }
}

/// High-performance object pool for SIP messages
pub struct SipMessagePool {
    pool: Arc<Mutex<VecDeque<SipMessage>>>,
    max_size: usize,
}

impl SipMessagePool {
    /// Create new SIP message pool with configuration
    pub fn new(config: PoolConfig) -> Self {
        let mut pool = VecDeque::with_capacity(config.initial_size);
        
        // Pre-allocate if requested
        if config.pre_allocate {
            for _ in 0..config.initial_size {
                pool.push_back(SipMessage::new_pooled());
            }
        }
        
        Self {
            pool: Arc::new(Mutex::new(pool)),
            max_size: if config.max_size == 0 { 1000 } else { config.max_size },
        }
    }

    /// Get a SIP message from the pool (or create new if pool empty)
    pub fn get(&self) -> PooledSipMessage {
        let mut pool = self.pool.lock().unwrap();
        
        if let Some(mut msg) = pool.pop_front() {
            // Reuse existing message
            msg.reset_for_reuse();
            PooledSipMessage::new(msg, self.pool.clone(), self.max_size)
        } else {
            // Create new message
            PooledSipMessage::new(
                SipMessage::new_pooled(),
                self.pool.clone(),
                self.max_size
            )
        }
    }

    /// Get current pool size
    pub fn size(&self) -> usize {
        self.pool.lock().unwrap().len()
    }
}

/// RAII wrapper for pooled SIP messages
/// Automatically returns message to pool when dropped
pub struct PooledSipMessage {
    message: Option<SipMessage>,
    pool: Arc<Mutex<VecDeque<SipMessage>>>,
    max_size: usize,
}

impl PooledSipMessage {
    fn new(message: SipMessage, pool: Arc<Mutex<VecDeque<SipMessage>>>, max_size: usize) -> Self {
        Self {
            message: Some(message),
            pool,
            max_size,
        }
    }

    /// Get mutable reference to the underlying SIP message
    pub fn message_mut(&mut self) -> &mut SipMessage {
        self.message.as_mut().unwrap()
    }

    /// Get reference to the underlying SIP message
    pub fn message(&self) -> &SipMessage {
        self.message.as_ref().unwrap()
    }

    /// Parse SIP message from string data
    pub fn parse_from_str(&mut self, data: &str) -> SsbcResult<()> {
        if let Some(ref mut msg) = self.message {
            msg.set_raw_message(data);
            msg.parse().map_err(|e| SsbcError::parse_error(e.to_string(), None, None))
        } else {
            unreachable!("PooledSipMessage should always contain a message")
        }
    }

    /// Consume the pooled message and return the inner SIP message
    /// The message will NOT be returned to the pool
    pub fn into_inner(mut self) -> SipMessage {
        self.message.take().unwrap()
    }
}

impl Drop for PooledSipMessage {
    fn drop(&mut self) {
        if let Some(message) = self.message.take() {
            // Return to pool if not at capacity
            if let Ok(mut pool) = self.pool.lock() {
                if pool.len() < self.max_size {
                    pool.push_back(message);
                }
                // Otherwise let it drop naturally
            }
        }
    }
}

/// Thread-safe global SIP message pool
static mut GLOBAL_POOL: Option<SipMessagePool> = None;
static POOL_INIT: std::sync::Once = std::sync::Once::new();

/// Initialize global SIP message pool
pub fn initialize_global_pool(config: PoolConfig) {
    POOL_INIT.call_once(|| {
        unsafe {
            GLOBAL_POOL = Some(SipMessagePool::new(config));
        }
    });
}

/// Get message from global pool
pub fn get_pooled_message() -> PooledSipMessage {
    POOL_INIT.call_once(|| {
        unsafe {
            GLOBAL_POOL = Some(SipMessagePool::new(PoolConfig::default()));
        }
    });
    
    unsafe {
        GLOBAL_POOL.as_ref().unwrap().get()
    }
}

// Extensions to SipMessage for pooling support
impl SipMessage {
    /// Create a new SIP message optimized for pooling
    pub fn new_pooled() -> Self {
        Self::new(String::new())
    }

    /// Reset message for reuse in pool
    pub fn reset_for_reuse(&mut self) {
        // Reset internal state
        *self = Self::new(String::new());
    }

    /// Set raw message data (for pooled reuse)
    pub fn set_raw_message(&mut self, data: &str) {
        *self = Self::new_from_str(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_pool_operations() {
        let config = PoolConfig {
            initial_size: 5,
            max_size: 10,
            pre_allocate: true,
        };
        
        let pool = SipMessagePool::new(config);
        assert_eq!(pool.size(), 5);
        
        // Get message from pool
        let pooled_msg = pool.get();
        assert_eq!(pool.size(), 4);
        
        // Message should be returned when dropped
        drop(pooled_msg);
        assert_eq!(pool.size(), 5);
    }

    #[test]
    fn test_pool_capacity_limit() {
        let config = PoolConfig {
            initial_size: 1,
            max_size: 2,
            pre_allocate: true,
        };
        
        let pool = SipMessagePool::new(config);
        
        // Get more messages than max size
        let _msg1 = pool.get();
        let _msg2 = pool.get();
        let _msg3 = pool.get();
        
        // Pool should not exceed max size when messages are dropped
        drop(_msg1);
        drop(_msg2);
        drop(_msg3);
        
        assert!(pool.size() <= 2);
    }

    #[test]
    fn test_pooled_message_parsing() {
        let pool = SipMessagePool::new(PoolConfig::default());
        
        let mut pooled_msg = pool.get();
        let sip_data = "INVITE sip:test@example.com SIP/2.0\r\nFrom: <sip:caller@example.com>\r\nTo: <sip:test@example.com>\r\nCall-ID: test123\r\nCSeq: 1 INVITE\r\nVia: SIP/2.0/UDP 192.168.1.1:5060\r\nMax-Forwards: 70\r\n\r\n";
        
        assert!(pooled_msg.parse_from_str(sip_data).is_ok());
        assert_eq!(pooled_msg.message().call_id().unwrap(), "test123");
    }

    #[test]
    fn test_global_pool() {
        initialize_global_pool(PoolConfig::default());
        
        let mut msg = get_pooled_message();
        let sip_data = "INVITE sip:test@example.com SIP/2.0\r\nFrom: <sip:caller@example.com>\r\nTo: <sip:test@example.com>\r\nCall-ID: global-test\r\nCSeq: 1 INVITE\r\nVia: SIP/2.0/UDP 192.168.1.1:5060\r\nMax-Forwards: 70\r\n\r\n";
        
        assert!(msg.parse_from_str(sip_data).is_ok());
        assert_eq!(msg.message().call_id().unwrap(), "global-test");
    }
}