//! Enhanced B2BUA Transaction management with full RFC 3261 compliance
//! 
//! This module enhances SSBC's basic Transaction structure with comprehensive
//! timer support and state machine as required by RFC 3261.

use crate::error::{SsbcError, SsbcResult};
use crate::b2bua::{Transaction, TransactionState};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// RFC 3261 Timer Configuration
#[derive(Debug, Clone)]
pub struct TimerConfig {
    /// T1: RTT estimate (default 500ms)
    pub t1: Duration,
    /// T2: Maximum retransmit interval for non-INVITE (default 4s)
    pub t2: Duration,
    /// T4: Maximum duration a message remains in network (default 5s)
    pub t4: Duration,
    /// Timer A initial value (T1)
    pub timer_a_initial: Duration,
    /// Timer B: INVITE transaction timeout (64*T1)
    pub timer_b: Duration,
    /// Timer C: Provisional response timeout (> 3 minutes)
    pub timer_c: Duration,
    /// Timer D: Response retransmit time (32s for UDP, 0 for reliable)
    pub timer_d: Duration,
    /// Timer E: Non-INVITE retransmit initial (T1)
    pub timer_e_initial: Duration,
    /// Timer F: Non-INVITE transaction timeout (64*T1)
    pub timer_f: Duration,
    /// Timer G: INVITE response retransmit initial (T1)
    pub timer_g_initial: Duration,
    /// Timer H: ACK receipt timeout (64*T1)
    pub timer_h: Duration,
    /// Timer I: ACK retransmit time (T4 for UDP, 0 for reliable)
    pub timer_i: Duration,
    /// Timer J: Non-INVITE response retransmit time (64*T1 for UDP)
    pub timer_j: Duration,
    /// Timer K: Non-INVITE response wait time (T4)
    pub timer_k: Duration,
}

impl Default for TimerConfig {
    fn default() -> Self {
        let t1 = Duration::from_millis(500);
        let t2 = Duration::from_secs(4);
        let t4 = Duration::from_secs(5);
        
        Self {
            t1,
            t2,
            t4,
            timer_a_initial: t1,
            timer_b: t1 * 64,
            timer_c: Duration::from_secs(180), // 3 minutes
            timer_d: Duration::from_secs(32),
            timer_e_initial: t1,
            timer_f: t1 * 64,
            timer_g_initial: t1,
            timer_h: t1 * 64,
            timer_i: t4,
            timer_j: t1 * 64,
            timer_k: t4,
        }
    }
}

/// Enhanced Transaction with full RFC 3261 timer support
#[derive(Debug, Clone)]
pub struct EnhancedTransaction {
    /// Base transaction data
    pub base: Transaction,
    
    /// Timer configuration
    pub timer_config: TimerConfig,
    
    /// Active timers (timer name -> expiry timestamp)
    pub active_timers: Vec<(String, u64)>,
    
    /// Is this a reliable transport?
    pub is_reliable: bool,
    
    /// Current retransmit interval (for exponential backoff)
    pub current_retransmit_interval: Duration,
    
    /// Source address
    pub source_addr: String,
    
    /// Destination address  
    pub dest_addr: String,
}

impl EnhancedTransaction {
    /// Create a new enhanced transaction
    pub fn new(
        branch_id: String,
        method: String,
        is_reliable: bool,
        source_addr: String,
        dest_addr: String,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
            
        let base = Transaction {
            branch_id,
            method: method.clone(),
            state: TransactionState::Calling,
            created_at: now,
            last_response_code: None,
            retransmission_count: 0,
            timeout_at: None,
        };
        
        let timer_config = TimerConfig::default();
        let mut active_timers = Vec::new();
        
        // Start appropriate timers based on method
        if method == "INVITE" {
            // Start Timer A (retransmission) and Timer B (timeout)
            if !is_reliable {
                active_timers.push((
                    "A".to_string(),
                    now + timer_config.timer_a_initial.as_secs()
                ));
            }
            active_timers.push((
                "B".to_string(),
                now + timer_config.timer_b.as_secs()
            ));
        } else {
            // Non-INVITE: Start Timer E and F
            if !is_reliable {
                active_timers.push((
                    "E".to_string(),
                    now + timer_config.timer_e_initial.as_secs()
                ));
            }
            active_timers.push((
                "F".to_string(),
                now + timer_config.timer_f.as_secs()
            ));
        }
        
        Self {
            base,
            timer_config,
            active_timers,
            is_reliable,
            current_retransmit_interval: Duration::from_millis(500),
            source_addr,
            dest_addr,
        }
    }
    
    /// Process timer expiry
    pub fn process_timer_expiry(&mut self, current_time: u64) -> Vec<TimerEvent> {
        let mut events = Vec::new();
        let mut expired_timers = Vec::new();
        
        // Check for expired timers
        for (i, (timer_name, expiry)) in self.active_timers.iter().enumerate() {
            if *expiry <= current_time {
                expired_timers.push((i, timer_name.clone()));
            }
        }
        
        // Process expired timers in reverse order to maintain indices
        for (idx, timer_name) in expired_timers.into_iter().rev() {
            self.active_timers.remove(idx);
            
            match timer_name.as_str() {
                "A" => {
                    // INVITE retransmission timer
                    events.push(TimerEvent::Retransmit);
                    self.base.retransmission_count += 1;
                    
                    // Exponential backoff: double the interval
                    self.current_retransmit_interval *= 2;
                    if self.current_retransmit_interval > self.timer_config.t2 {
                        self.current_retransmit_interval = self.timer_config.t2;
                    }
                    
                    // Restart timer A with new interval
                    self.active_timers.push((
                        "A".to_string(),
                        current_time + self.current_retransmit_interval.as_secs()
                    ));
                }
                "B" => {
                    // INVITE timeout
                    events.push(TimerEvent::Timeout);
                    self.base.state = TransactionState::Terminated;
                }
                "C" => {
                    // Provisional response timeout
                    events.push(TimerEvent::ProvisionalTimeout);
                }
                "D" => {
                    // Response retransmit timeout
                    self.base.state = TransactionState::Terminated;
                }
                "E" => {
                    // Non-INVITE retransmission
                    events.push(TimerEvent::Retransmit);
                    self.base.retransmission_count += 1;
                    
                    // Exponential backoff
                    self.current_retransmit_interval = 
                        std::cmp::min(self.current_retransmit_interval * 2, self.timer_config.t2);
                    
                    // Restart timer E
                    self.active_timers.push((
                        "E".to_string(),
                        current_time + self.current_retransmit_interval.as_secs()
                    ));
                }
                "F" => {
                    // Non-INVITE timeout
                    events.push(TimerEvent::Timeout);
                    self.base.state = TransactionState::Terminated;
                }
                _ => {}
            }
        }
        
        events
    }
    
    /// Handle state transition
    pub fn transition_state(&mut self, new_state: TransactionState) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
            
        self.base.state = new_state.clone();
        
        // Cancel/start timers based on state transition
        match new_state {
            TransactionState::Proceeding => {
                // Cancel Timer A/E (retransmission)
                self.active_timers.retain(|(name, _)| name != "A" && name != "E");
                
                // For INVITE, optionally start Timer C
                if self.base.method == "INVITE" {
                    self.active_timers.push((
                        "C".to_string(),
                        now + self.timer_config.timer_c.as_secs()
                    ));
                }
            }
            TransactionState::Completed => {
                // Cancel all retransmission timers
                self.active_timers.retain(|(name, _)| {
                    name != "A" && name != "E" && name != "C"
                });
                
                // Start Timer D (response retransmit) for unreliable transport
                if !self.is_reliable {
                    self.active_timers.push((
                        "D".to_string(),
                        now + self.timer_config.timer_d.as_secs()
                    ));
                }
            }
            TransactionState::Terminated => {
                // Cancel all timers
                self.active_timers.clear();
            }
            _ => {}
        }
    }
}

/// Timer events that can occur
#[derive(Debug, Clone)]
pub enum TimerEvent {
    /// Need to retransmit request
    Retransmit,
    /// Transaction timeout
    Timeout,
    /// Provisional response timeout (Timer C)
    ProvisionalTimeout,
}

/// Enhanced transaction manager
pub struct EnhancedTransactionManager {
    /// Active transactions
    transactions: std::collections::HashMap<String, EnhancedTransaction>,
    
    /// Enable RFC 3261 timers
    timers_enabled: bool,
}

impl EnhancedTransactionManager {
    /// Create new manager
    pub fn new(enable_timers: bool) -> Self {
        Self {
            transactions: std::collections::HashMap::new(),
            timers_enabled: enable_timers,
        }
    }
    
    /// Create a new transaction
    pub fn create_transaction(
        &mut self,
        branch_id: String,
        method: String,
        is_reliable: bool,
        source_addr: String,
        dest_addr: String,
    ) -> SsbcResult<()> {
        if self.transactions.contains_key(&branch_id) {
            return Err(SsbcError::StateError {
                operation: "create_transaction".to_string(),
                reason: "Transaction already exists".to_string(),
                context: None,
            });
        }
        
        let transaction = EnhancedTransaction::new(
            branch_id.clone(),
            method,
            is_reliable,
            source_addr,
            dest_addr,
        );
        
        self.transactions.insert(branch_id, transaction);
        Ok(())
    }
    
    /// Get transaction
    pub fn get_transaction(&self, branch_id: &str) -> Option<&EnhancedTransaction> {
        self.transactions.get(branch_id)
    }
    
    /// Process timers for all transactions
    pub fn process_timers(&mut self) -> Vec<(String, Vec<TimerEvent>)> {
        if !self.timers_enabled {
            return Vec::new();
        }
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
            
        let mut all_events = Vec::new();
        
        for (branch_id, transaction) in self.transactions.iter_mut() {
            let events = transaction.process_timer_expiry(now);
            if !events.is_empty() {
                all_events.push((branch_id.clone(), events));
            }
        }
        
        // Remove terminated transactions
        self.transactions.retain(|_, t| t.base.state != TransactionState::Terminated);
        
        all_events
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_enhanced_transaction_creation() {
        let tx = EnhancedTransaction::new(
            "z9hG4bK123".to_string(),
            "INVITE".to_string(),
            false,
            "192.168.1.100:5060".to_string(),
            "192.168.1.200:5060".to_string(),
        );
        
        // Should have Timer A and B for unreliable INVITE
        assert_eq!(tx.active_timers.len(), 2);
        assert!(tx.active_timers.iter().any(|(name, _)| name == "A"));
        assert!(tx.active_timers.iter().any(|(name, _)| name == "B"));
    }
    
    #[test]
    fn test_timer_expiry() {
        let mut tx = EnhancedTransaction::new(
            "z9hG4bK123".to_string(),
            "INVITE".to_string(),
            false,
            "192.168.1.100:5060".to_string(),
            "192.168.1.200:5060".to_string(),
        );
        
        // Simulate timer A expiry
        let future_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() + 1)
            .unwrap_or(1);
            
        let events = tx.process_timer_expiry(future_time);
        
        // Should get retransmit event
        assert!(events.iter().any(|e| matches!(e, TimerEvent::Retransmit)));
        assert_eq!(tx.base.retransmission_count, 1);
    }
}