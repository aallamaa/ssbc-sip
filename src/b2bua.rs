//! B2BUA (Back-to-Back User Agent) state management
//! 
//! Provides carrier-grade call state management, transaction handling,
//! and media relay capabilities for SIP proxy operations.

use crate::error::{SsbcError, SsbcResult};
use crate::sdp::SessionDescription;
use std::collections::HashMap;
use std::time::{SystemTime, Duration, UNIX_EPOCH};

/// Call state in B2BUA
#[derive(Debug, Clone, PartialEq)]
pub enum CallState {
    /// Initial state - no call established
    Idle,
    /// INVITE received/sent, waiting for response
    Calling,
    /// 1xx response received/sent
    Proceeding,
    /// 200 OK received/sent, waiting for ACK
    Connecting,
    /// Call established (ACK received/sent)
    Connected,
    /// BYE received/sent
    Disconnecting,
    /// Call terminated
    Terminated,
    /// Error state
    Failed(String),
}

/// Transaction state for SIP requests
#[derive(Debug, Clone, PartialEq)]
pub enum TransactionState {
    Calling,
    Proceeding,
    Completed,
    Confirmed,
    Terminated,
}

/// Represents a SIP dialog (call session)
#[derive(Debug, Clone)]
pub struct Dialog {
    pub call_id: String,
    pub local_tag: String,
    pub remote_tag: Option<String>,
    pub local_uri: String,
    pub remote_uri: String,
    pub local_cseq: u32,
    pub remote_cseq: u32,
    pub state: CallState,
    pub created_at: u64,
    pub last_activity: u64,
    pub route_set: Vec<String>,
    pub contact: Option<String>,
    pub sdp: Option<SessionDescription>,
}

/// B2BUA leg representing one side of the call
#[derive(Debug, Clone)]
pub struct CallLeg {
    pub dialog: Dialog,
    pub transactions: HashMap<String, Transaction>, // Branch ID -> Transaction
    pub media_relay: Option<MediaRelay>,
    pub peer_leg_id: Option<String>,
}

/// SIP transaction
#[derive(Debug, Clone)]
pub struct Transaction {
    pub branch_id: String,
    pub method: String,
    pub state: TransactionState,
    pub created_at: u64,
    pub last_response_code: Option<u16>,
    pub retransmission_count: u32,
    pub timeout_at: Option<u64>,
}

/// Media relay information
#[derive(Debug, Clone)]
pub struct MediaRelay {
    pub local_rtp_port: u16,
    pub local_rtcp_port: u16,
    pub remote_rtp_address: String,
    pub remote_rtp_port: u16,
    pub codec_info: Vec<String>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
}

/// B2BUA call manager
pub struct B2buaManager {
    calls: HashMap<String, CallLeg>, // Call-ID -> CallLeg
    call_pairs: HashMap<String, String>, // Leg A Call-ID -> Leg B Call-ID
    transactions: HashMap<String, String>, // Transaction ID -> Call-ID
    max_calls: usize,
    call_timeout_seconds: u64,
    transaction_timeout_seconds: u64,
}

impl B2buaManager {
    /// Create new B2BUA manager
    pub fn new(max_calls: usize, call_timeout_seconds: u64, transaction_timeout_seconds: u64) -> Self {
        Self {
            calls: HashMap::new(),
            call_pairs: HashMap::new(),
            transactions: HashMap::new(),
            max_calls,
            call_timeout_seconds,
            transaction_timeout_seconds,
        }
    }

    /// Process incoming INVITE (create new call)
    pub fn handle_invite(&mut self, 
                        call_id: &str, 
                        from_uri: &str, 
                        to_uri: &str,
                        from_tag: &str,
                        cseq: u32,
                        sdp: Option<SessionDescription>) -> SsbcResult<String> {
        
        // Check capacity
        if self.calls.len() >= self.max_calls {
            return Err(SsbcError::resource_error(
                crate::error::ResourceType::ConcurrentCalls,
                self.calls.len() as u64,
                self.max_calls as u64
            ));
        }

        let now = current_timestamp();
        
        // Create incoming call leg
        let dialog = Dialog {
            call_id: call_id.to_string(),
            local_tag: generate_tag(),
            remote_tag: Some(from_tag.to_string()),
            local_uri: to_uri.to_string(),
            remote_uri: from_uri.to_string(),
            local_cseq: 1,
            remote_cseq: cseq,
            state: CallState::Calling,
            created_at: now,
            last_activity: now,
            route_set: Vec::new(),
            contact: None,
            sdp,
        };

        let call_leg = CallLeg {
            dialog,
            transactions: HashMap::new(),
            media_relay: None,
            peer_leg_id: None,
        };

        self.calls.insert(call_id.to_string(), call_leg);
        Ok(call_id.to_string())
    }

    /// Create outgoing call leg (B2BUA forwards the call)
    pub fn create_outgoing_call(&mut self, 
                               incoming_call_id: &str,
                               destination_uri: &str,
                               sdp: Option<SessionDescription>) -> SsbcResult<String> {
        
        // Generate new call ID for outgoing leg
        let outgoing_call_id = generate_call_id();
        let now = current_timestamp();

        // Get incoming call info
        let incoming_call = self.calls.get(incoming_call_id)
            .ok_or_else(|| SsbcError::StateError {
                operation: "create_outgoing_call".to_string(),
                reason: "Incoming call not found".to_string(),
                context: None,
            })?;

        // Create outgoing dialog
        let dialog = Dialog {
            call_id: outgoing_call_id.clone(),
            local_tag: generate_tag(),
            remote_tag: None, // Will be set when response received
            local_uri: "sip:b2bua@localhost".to_string(), // B2BUA identity
            remote_uri: destination_uri.to_string(),
            local_cseq: 1,
            remote_cseq: 0,
            state: CallState::Calling,
            created_at: now,
            last_activity: now,
            route_set: Vec::new(),
            contact: None,
            sdp,
        };

        let outgoing_leg = CallLeg {
            dialog,
            transactions: HashMap::new(),
            media_relay: None,
            peer_leg_id: Some(incoming_call_id.to_string()),
        };

        // Link the legs
        self.calls.insert(outgoing_call_id.clone(), outgoing_leg);
        self.call_pairs.insert(incoming_call_id.to_string(), outgoing_call_id.clone());
        self.call_pairs.insert(outgoing_call_id.clone(), incoming_call_id.to_string());

        // Update incoming leg with peer reference
        if let Some(incoming_leg) = self.calls.get_mut(incoming_call_id) {
            incoming_leg.peer_leg_id = Some(outgoing_call_id.clone());
        }

        Ok(outgoing_call_id)
    }

    /// Handle SIP response
    pub fn handle_response(&mut self, 
                          call_id: &str, 
                          status_code: u16, 
                          to_tag: Option<&str>,
                          sdp: Option<SessionDescription>) -> SsbcResult<()> {
        
        let call_leg = self.calls.get_mut(call_id)
            .ok_or_else(|| SsbcError::StateError {
                operation: "handle_response".to_string(),
                reason: "Call not found".to_string(),
                context: None,
            })?;

        // Update to tag if provided
        if let Some(tag) = to_tag {
            call_leg.dialog.remote_tag = Some(tag.to_string());
        }

        // Update SDP if provided
        if let Some(session_desc) = sdp {
            call_leg.dialog.sdp = Some(session_desc);
        }

        // State transitions based on response code
        call_leg.dialog.state = match status_code {
            100..=199 => CallState::Proceeding,
            200..=299 => CallState::Connecting,
            300..=699 => CallState::Failed(format!("Response {}", status_code)),
            _ => return Err(SsbcError::StateError {
                operation: "handle_response".to_string(),
                reason: format!("Invalid status code: {}", status_code),
                context: None,
            }),
        };

        call_leg.dialog.last_activity = current_timestamp();
        Ok(())
    }

    /// Handle ACK (call establishment)
    pub fn handle_ack(&mut self, call_id: &str) -> SsbcResult<()> {
        let call_leg = self.calls.get_mut(call_id)
            .ok_or_else(|| SsbcError::StateError {
                operation: "handle_ack".to_string(),
                reason: "Call not found".to_string(),
                context: None,
            })?;

        // Validate state transition
        if call_leg.dialog.state != CallState::Connecting {
            return Err(SsbcError::StateError {
                operation: "handle_ack".to_string(),
                reason: "Invalid state for ACK".to_string(),
                context: None,
            });
        }

        call_leg.dialog.state = CallState::Connected;
        call_leg.dialog.last_activity = current_timestamp();
        Ok(())
    }

    /// Handle BYE (call termination)
    pub fn handle_bye(&mut self, call_id: &str) -> SsbcResult<Option<String>> {
        let peer_call_id = self.call_pairs.get(call_id).cloned();
        
        // Update call state
        if let Some(call_leg) = self.calls.get_mut(call_id) {
            call_leg.dialog.state = CallState::Disconnecting;
            call_leg.dialog.last_activity = current_timestamp();
        }

        Ok(peer_call_id)
    }

    /// Terminate call and cleanup
    pub fn terminate_call(&mut self, call_id: &str) -> SsbcResult<Option<String>> {
        let peer_call_id = self.call_pairs.get(call_id).cloned();
        
        // Remove call leg
        if let Some(mut call_leg) = self.calls.remove(call_id) {
            call_leg.dialog.state = CallState::Terminated;
        }

        // Clean up pairing
        self.call_pairs.remove(call_id);
        if let Some(ref peer_id) = peer_call_id {
            self.call_pairs.remove(peer_id);
        }

        // Clean up transactions
        self.transactions.retain(|_, cid| cid != call_id);

        Ok(peer_call_id)
    }

    /// Setup media relay between call legs
    pub fn setup_media_relay(&mut self, 
                             call_id_a: &str, 
                             call_id_b: &str,
                             local_rtp_port_a: u16,
                             local_rtp_port_b: u16) -> SsbcResult<()> {
        
        // Get call leg information
        let leg_a_info = self.calls.get(call_id_a)
            .ok_or_else(|| SsbcError::StateError {
                operation: "setup_media_relay".to_string(),
                reason: "Call A not found".to_string(),
                context: None,
            })?;

        let leg_b_info = self.calls.get(call_id_b)
            .ok_or_else(|| SsbcError::StateError {
                operation: "setup_media_relay".to_string(),
                reason: "Call B not found".to_string(),
                context: None,
            })?;

        // Extract media information from SDP
        let (remote_addr_a, remote_port_a) = if let Some(ref sdp) = leg_a_info.dialog.sdp {
            extract_media_info(sdp)?
        } else {
            return Err(SsbcError::StateError {
                operation: "setup_media_relay".to_string(),
                reason: "No SDP in call A".to_string(),
                context: None,
            });
        };

        let (remote_addr_b, remote_port_b) = if let Some(ref sdp) = leg_b_info.dialog.sdp {
            extract_media_info(sdp)?
        } else {
            return Err(SsbcError::StateError {
                operation: "setup_media_relay".to_string(),
                reason: "No SDP in call B".to_string(),
                context: None,
            });
        };

        // Create media relay for leg A (points to leg B)
        let relay_a = MediaRelay {
            local_rtp_port: local_rtp_port_a,
            local_rtcp_port: local_rtp_port_a + 1,
            remote_rtp_address: remote_addr_b,
            remote_rtp_port: remote_port_b,
            codec_info: vec!["PCMU".to_string()], // TODO: Extract from SDP
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
        };

        // Create media relay for leg B (points to leg A)
        let relay_b = MediaRelay {
            local_rtp_port: local_rtp_port_b,
            local_rtcp_port: local_rtp_port_b + 1,
            remote_rtp_address: remote_addr_a,
            remote_rtp_port: remote_port_a,
            codec_info: vec!["PCMU".to_string()], // TODO: Extract from SDP
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
        };

        // Update call legs with media relay info
        if let Some(call_leg) = self.calls.get_mut(call_id_a) {
            call_leg.media_relay = Some(relay_a);
        }

        if let Some(call_leg) = self.calls.get_mut(call_id_b) {
            call_leg.media_relay = Some(relay_b);
        }

        Ok(())
    }

    /// Get call statistics
    pub fn get_call_stats(&self) -> CallStats {
        let mut stats = CallStats {
            total_calls: self.calls.len(),
            active_calls: 0,
            connected_calls: 0,
            failed_calls: 0,
            average_call_duration: 0.0,
            total_media_bytes: 0,
        };

        let now = current_timestamp();
        let mut total_duration = 0u64;
        let mut duration_count = 0;

        for call_leg in self.calls.values() {
            match call_leg.dialog.state {
                CallState::Connected => {
                    stats.active_calls += 1;
                    stats.connected_calls += 1;
                    total_duration += now - call_leg.dialog.created_at;
                    duration_count += 1;
                },
                CallState::Calling | CallState::Proceeding | CallState::Connecting => {
                    stats.active_calls += 1;
                },
                CallState::Failed(_) => {
                    stats.failed_calls += 1;
                },
                _ => {},
            }

            if let Some(ref relay) = call_leg.media_relay {
                stats.total_media_bytes += relay.bytes_sent + relay.bytes_received;
            }
        }

        if duration_count > 0 {
            stats.average_call_duration = total_duration as f64 / duration_count as f64;
        }

        stats
    }

    /// Cleanup expired calls and transactions
    pub fn cleanup_expired(&mut self) -> SsbcResult<Vec<String>> {
        let now = current_timestamp();
        let call_timeout = self.call_timeout_seconds;
        let mut expired_calls = Vec::new();

        // Find expired calls
        let expired: Vec<String> = self.calls.iter()
            .filter(|(_, call_leg)| {
                now - call_leg.dialog.last_activity > call_timeout
            })
            .map(|(call_id, _)| call_id.clone())
            .collect();

        // Terminate expired calls
        for call_id in expired {
            if let Some(peer_id) = self.terminate_call(&call_id)? {
                expired_calls.push(peer_id);
            }
            expired_calls.push(call_id);
        }

        Ok(expired_calls)
    }

    /// Get call by ID
    pub fn get_call(&self, call_id: &str) -> Option<&CallLeg> {
        self.calls.get(call_id)
    }

    /// Get peer call ID
    pub fn get_peer_call_id(&self, call_id: &str) -> Option<&String> {
        self.call_pairs.get(call_id)
    }
}

/// Call statistics
#[derive(Debug, Clone)]
pub struct CallStats {
    pub total_calls: usize,
    pub active_calls: usize,
    pub connected_calls: usize,
    pub failed_calls: usize,
    pub average_call_duration: f64,
    pub total_media_bytes: u64,
}

// Helper functions

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn generate_tag() -> String {
    format!("tag-{}-{}", current_timestamp(), rand::random::<u32>())
}

fn generate_call_id() -> String {
    format!("call-{}-{}", current_timestamp(), rand::random::<u32>())
}

fn extract_media_info(sdp: &SessionDescription) -> SsbcResult<(String, u16)> {
    // Get connection address
    let address = if let Some(ref conn) = sdp.connection {
        conn.connection_address.clone()
    } else {
        return Err(SsbcError::StateError {
            operation: "extract_media_info".to_string(),
            reason: "No connection information in SDP".to_string(),
            context: None,
        });
    };

    // Get first audio media port
    for media in &sdp.media_descriptions {
        if media.media_type == "audio" {
            return Ok((address, media.port));
        }
    }

    Err(SsbcError::StateError {
        operation: "extract_media_info".to_string(),
        reason: "No audio media found in SDP".to_string(),
        context: None,
    })
}

// Add rand dependency for ID generation
mod rand {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::time::SystemTime;

    pub fn random<T>() -> T 
    where 
        T: From<u32>
    {
        let mut hasher = DefaultHasher::new();
        SystemTime::now().hash(&mut hasher);
        T::from(hasher.finish() as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_b2bua_call_creation() {
        let mut b2bua = B2buaManager::new(100, 3600, 32);
        
        let call_id = b2bua.handle_invite(
            "test-call-id",
            "sip:caller@example.com",
            "sip:callee@example.com", 
            "caller-tag",
            1,
            None
        ).unwrap();

        assert_eq!(call_id, "test-call-id");
        assert!(b2bua.get_call(&call_id).is_some());
    }

    #[test]
    fn test_b2bua_state_transitions() {
        let mut b2bua = B2buaManager::new(100, 3600, 32);
        
        // Create call
        let call_id = "test-call-id";
        b2bua.handle_invite(call_id, "sip:a@test.com", "sip:b@test.com", "tag1", 1, None).unwrap();
        
        // Send 200 OK
        b2bua.handle_response(call_id, 200, Some("tag2"), None).unwrap();
        assert_eq!(b2bua.get_call(call_id).unwrap().dialog.state, CallState::Connecting);
        
        // Send ACK
        b2bua.handle_ack(call_id).unwrap();
        assert_eq!(b2bua.get_call(call_id).unwrap().dialog.state, CallState::Connected);
        
        // Send BYE
        b2bua.handle_bye(call_id).unwrap();
        assert_eq!(b2bua.get_call(call_id).unwrap().dialog.state, CallState::Disconnecting);
    }

    #[test]
    fn test_call_pairing() {
        let mut b2bua = B2buaManager::new(100, 3600, 32);
        
        // Create incoming call
        let incoming_id = "incoming-call";
        b2bua.handle_invite(incoming_id, "sip:a@test.com", "sip:b@test.com", "tag1", 1, None).unwrap();
        
        // Create outgoing call
        let outgoing_id = b2bua.create_outgoing_call(incoming_id, "sip:c@test.com", None).unwrap();
        
        // Verify pairing
        assert_eq!(b2bua.get_peer_call_id(incoming_id), Some(&outgoing_id));
        assert_eq!(b2bua.get_peer_call_id(&outgoing_id), Some(&incoming_id.to_string()));
    }

    #[test]
    fn test_capacity_limits() {
        let mut b2bua = B2buaManager::new(2, 3600, 32); // Max 2 calls
        
        // Fill to capacity
        b2bua.handle_invite("call1", "sip:a@test.com", "sip:b@test.com", "tag1", 1, None).unwrap();
        b2bua.handle_invite("call2", "sip:c@test.com", "sip:d@test.com", "tag2", 1, None).unwrap();
        
        // Third call should fail
        let result = b2bua.handle_invite("call3", "sip:e@test.com", "sip:f@test.com", "tag3", 1, None);
        assert!(result.is_err());
    }
}