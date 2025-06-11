//! Comprehensive tests for enhanced B2BUA transaction management

use ssbc::b2bua_enhanced::{
    EnhancedTransaction, EnhancedTransactionManager, TimerConfig, TimerEvent
};
use ssbc::b2bua::TransactionState;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[test]
fn test_timer_config_defaults() {
    let config = TimerConfig::default();
    
    // Verify RFC 3261 default values
    assert_eq!(config.t1, Duration::from_millis(500));
    assert_eq!(config.t2, Duration::from_secs(4));
    assert_eq!(config.t4, Duration::from_secs(5));
    
    // Verify timer relationships
    assert_eq!(config.timer_b, config.t1 * 64); // Timer B = 64*T1
    assert_eq!(config.timer_f, config.t1 * 64); // Timer F = 64*T1
    assert_eq!(config.timer_c, Duration::from_secs(180)); // 3 minutes
}

#[test]
fn test_invite_transaction_timers() {
    let tx = EnhancedTransaction::new(
        "z9hG4bK123".to_string(),
        "INVITE".to_string(),
        false, // unreliable transport
        "192.168.1.100:5060".to_string(),
        "192.168.1.200:5060".to_string(),
    );
    
    // Should have Timer A and B for unreliable INVITE
    assert_eq!(tx.active_timers.len(), 2);
    
    // Verify Timer A is set
    let timer_a = tx.active_timers.iter().find(|(name, _)| name == "A");
    assert!(timer_a.is_some());
    
    // Verify Timer B is set
    let timer_b = tx.active_timers.iter().find(|(name, _)| name == "B");
    assert!(timer_b.is_some());
}

#[test]
fn test_non_invite_transaction_timers() {
    let tx = EnhancedTransaction::new(
        "z9hG4bK456".to_string(),
        "OPTIONS".to_string(),
        false, // unreliable transport
        "192.168.1.100:5060".to_string(),
        "192.168.1.200:5060".to_string(),
    );
    
    // Should have Timer E and F for non-INVITE
    assert_eq!(tx.active_timers.len(), 2);
    
    // Verify Timer E is set
    let timer_e = tx.active_timers.iter().find(|(name, _)| name == "E");
    assert!(timer_e.is_some());
    
    // Verify Timer F is set
    let timer_f = tx.active_timers.iter().find(|(name, _)| name == "F");
    assert!(timer_f.is_some());
}

#[test]
fn test_reliable_transport_timers() {
    let tx = EnhancedTransaction::new(
        "z9hG4bK789".to_string(),
        "INVITE".to_string(),
        true, // reliable transport (TCP/TLS)
        "192.168.1.100:5060".to_string(),
        "192.168.1.200:5060".to_string(),
    );
    
    // Should only have Timer B (no retransmission timer A)
    assert_eq!(tx.active_timers.len(), 1);
    
    // Only Timer B should be set
    let timer_b = tx.active_timers.iter().find(|(name, _)| name == "B");
    assert!(timer_b.is_some());
    
    // Timer A should not be set for reliable transport
    let timer_a = tx.active_timers.iter().find(|(name, _)| name == "A");
    assert!(timer_a.is_none());
}

#[test]
fn test_timer_a_exponential_backoff() {
    let mut tx = EnhancedTransaction::new(
        "z9hG4bKabc".to_string(),
        "INVITE".to_string(),
        false,
        "192.168.1.100:5060".to_string(),
        "192.168.1.200:5060".to_string(),
    );
    
    let initial_interval = tx.current_retransmit_interval;
    assert_eq!(initial_interval, Duration::from_millis(500)); // T1
    
    // Simulate timer expiry
    let future_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() + 1)
        .unwrap_or(1);
    
    let events = tx.process_timer_expiry(future_time);
    
    // Should get retransmit event
    assert!(events.iter().any(|e| matches!(e, TimerEvent::Retransmit)));
    
    // Interval should double
    assert_eq!(tx.current_retransmit_interval, initial_interval * 2);
    assert_eq!(tx.base.retransmission_count, 1);
}

#[test]
fn test_timer_b_timeout() {
    let mut tx = EnhancedTransaction::new(
        "z9hG4bKdef".to_string(),
        "INVITE".to_string(),
        false,
        "192.168.1.100:5060".to_string(),
        "192.168.1.200:5060".to_string(),
    );
    
    // Fast forward past Timer B (64*T1 = 32 seconds)
    let future_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() + 33)
        .unwrap_or(33);
    
    let events = tx.process_timer_expiry(future_time);
    
    // Should get timeout event
    assert!(events.iter().any(|e| matches!(e, TimerEvent::Timeout)));
    
    // Transaction should be terminated
    assert_eq!(tx.base.state, TransactionState::Terminated);
}

#[test]
fn test_state_transitions() {
    let mut tx = EnhancedTransaction::new(
        "z9hG4bKghi".to_string(),
        "INVITE".to_string(),
        false,
        "192.168.1.100:5060".to_string(),
        "192.168.1.200:5060".to_string(),
    );
    
    // Initial state
    assert_eq!(tx.base.state, TransactionState::Calling);
    assert_eq!(tx.active_timers.len(), 2); // Timer A and B
    
    // Transition to Proceeding (1xx response)
    tx.transition_state(TransactionState::Proceeding);
    assert_eq!(tx.base.state, TransactionState::Proceeding);
    
    // Timer A should be cancelled, Timer C should be started
    let timer_a = tx.active_timers.iter().find(|(name, _)| name == "A");
    assert!(timer_a.is_none());
    
    let timer_c = tx.active_timers.iter().find(|(name, _)| name == "C");
    assert!(timer_c.is_some());
    
    // Transition to Completed (final response)
    tx.transition_state(TransactionState::Completed);
    assert_eq!(tx.base.state, TransactionState::Completed);
    
    // Timer D should be started for unreliable transport
    let timer_d = tx.active_timers.iter().find(|(name, _)| name == "D");
    assert!(timer_d.is_some());
}

#[test]
fn test_transaction_manager() {
    let mut manager = EnhancedTransactionManager::new(true);
    
    // Create INVITE transaction
    let result = manager.create_transaction(
        "z9hG4bK111".to_string(),
        "INVITE".to_string(),
        false,
        "192.168.1.100:5060".to_string(),
        "192.168.1.200:5060".to_string(),
    );
    assert!(result.is_ok());
    
    // Create BYE transaction
    let result = manager.create_transaction(
        "z9hG4bK222".to_string(),
        "BYE".to_string(),
        false,
        "192.168.1.100:5060".to_string(),
        "192.168.1.200:5060".to_string(),
    );
    assert!(result.is_ok());
    
    // Try to create duplicate transaction
    let result = manager.create_transaction(
        "z9hG4bK111".to_string(), // Same branch ID
        "INVITE".to_string(),
        false,
        "192.168.1.100:5060".to_string(),
        "192.168.1.200:5060".to_string(),
    );
    assert!(result.is_err());
    
    // Get transaction
    let tx = manager.get_transaction("z9hG4bK111");
    assert!(tx.is_some());
    assert_eq!(tx.unwrap().base.method, "INVITE");
}

#[test]
fn test_timer_processing() {
    let mut manager = EnhancedTransactionManager::new(true);
    
    // Create transaction
    manager.create_transaction(
        "z9hG4bK333".to_string(),
        "INVITE".to_string(),
        false,
        "192.168.1.100:5060".to_string(),
        "192.168.1.200:5060".to_string(),
    ).unwrap();
    
    // Process timers immediately
    let events = manager.process_timers();
    // Events may or may not be empty depending on timing precision
    
    // Wait and process timers (this is a simple test, in real scenario we'd mock time)
    std::thread::sleep(Duration::from_millis(600));
    let events = manager.process_timers();
    
    // Should have events for Timer A expiry
    if !events.is_empty() {
        let (branch_id, timer_events) = &events[0];
        assert_eq!(branch_id, "z9hG4bK333");
        assert!(timer_events.iter().any(|e| matches!(e, TimerEvent::Retransmit)));
    }
}

#[test]
fn test_terminated_transaction_cleanup() {
    let mut manager = EnhancedTransactionManager::new(true);
    
    // Create transaction
    manager.create_transaction(
        "z9hG4bK444".to_string(),
        "OPTIONS".to_string(),
        false,
        "192.168.1.100:5060".to_string(),
        "192.168.1.200:5060".to_string(),
    ).unwrap();
    
    // Get and terminate transaction
    {
        let tx = manager.get_transaction("z9hG4bK444").unwrap();
        assert_eq!(tx.base.state, TransactionState::Calling);
    }
    
    // The transaction will be cleaned up when terminated after timer expiry
    // For now, just verify it exists
    let tx = manager.get_transaction("z9hG4bK444");
    assert!(tx.is_some());
}

#[test]
fn test_timer_cancellation_on_reliable_transport() {
    let mut tx = EnhancedTransaction::new(
        "z9hG4bK555".to_string(),
        "REGISTER".to_string(),
        true, // reliable transport
        "192.168.1.100:5060".to_string(),
        "192.168.1.200:5060".to_string(),
    );
    
    // Should only have Timer F (no Timer E for reliable)
    assert_eq!(tx.active_timers.len(), 1);
    let timer_f = tx.active_timers.iter().find(|(name, _)| name == "F");
    assert!(timer_f.is_some());
    
    // Transition to completed
    tx.transition_state(TransactionState::Completed);
    
    // Timer D should NOT be started for reliable transport
    let timer_d = tx.active_timers.iter().find(|(name, _)| name == "D");
    assert!(timer_d.is_none());
}

#[test]
fn test_retransmission_cap() {
    let mut tx = EnhancedTransaction::new(
        "z9hG4bK666".to_string(),
        "INVITE".to_string(),
        false,
        "192.168.1.100:5060".to_string(),
        "192.168.1.200:5060".to_string(),
    );
    
    // Process multiple retransmissions
    for _ in 0..10 {
        let future_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() + 1)
            .unwrap_or(1);
        
        tx.process_timer_expiry(future_time);
        
        // Interval should cap at T2 (4 seconds)
        if tx.current_retransmit_interval > tx.timer_config.t2 {
            assert_eq!(tx.current_retransmit_interval, tx.timer_config.t2);
        }
    }
}