//! Simplified SDP (Session Description Protocol) support for B2BUA
//! 
//! Focuses on essential SDP operations needed for B2BUA: address rewriting,
//! port changes, and basic codec filtering. Avoids complex RFC compliance.

use crate::error::{SsbcError, SsbcResult};

/// Simplified SDP session description
#[derive(Debug, Clone, PartialEq)]
pub struct SessionDescription {
    pub origin: Origin,
    pub session_name: String,
    pub connection: Option<Connection>,
    pub media_descriptions: Vec<MediaDescription>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Origin {
    pub username: String,
    pub session_id: String,
    pub session_version: String,
    pub unicast_address: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Connection {
    pub connection_address: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MediaDescription {
    pub media_type: String,      // audio, video
    pub port: u16,
    pub protocol: String,        // RTP/AVP
    pub formats: Vec<String>,    // Payload types
    pub connection: Option<Connection>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CodecInfo {
    pub payload_type: u8,
    pub name: String,
    pub clock_rate: u32,
}

impl SessionDescription {
    /// Parse SDP from string - simplified version
    pub fn parse(sdp: &str) -> SsbcResult<Self> {
        let lines: Vec<&str> = sdp.lines().collect();
        let mut session = SessionDescription {
            origin: Origin {
                username: "-".to_string(),
                session_id: "0".to_string(),
                session_version: "0".to_string(),
                unicast_address: "127.0.0.1".to_string(),
            },
            session_name: "SSBC".to_string(),
            connection: None,
            media_descriptions: Vec::new(),
        };

        let mut i = 0;
        while i < lines.len() {
            let line = lines[i];
            if line.len() < 2 || !line.chars().nth(1).map_or(false, |c| c == '=') {
                i += 1;
                continue;
            }

            let (field, value) = line.split_at(2);
            let value = value.trim();

            match field {
                "o=" => {
                    session.origin = parse_origin(value)?;
                },
                "s=" => {
                    session.session_name = value.to_string();
                },
                "c=" => {
                    session.connection = Some(parse_connection(value)?);
                },
                "m=" => {
                    let media = parse_media_description(value, &lines, &mut i)?;
                    session.media_descriptions.push(media);
                },
                _ => {},
            }
            i += 1;
        }

        Ok(session)
    }

    /// Convert back to SDP string
    pub fn to_string(&self) -> String {
        let mut result = String::new();
        
        result.push_str("v=0\r\n");
        result.push_str(&format!(
            "o={} {} {} IN IP4 {}\r\n",
            self.origin.username,
            self.origin.session_id,
            self.origin.session_version,
            self.origin.unicast_address
        ));
        result.push_str(&format!("s={}\r\n", self.session_name));
        
        if let Some(ref conn) = self.connection {
            result.push_str(&format!("c=IN IP4 {}\r\n", conn.connection_address));
        }
        
        result.push_str("t=0 0\r\n");
        
        for media in &self.media_descriptions {
            result.push_str(&format!(
                "m={} {} {} {}\r\n",
                media.media_type,
                media.port,
                media.protocol,
                media.formats.join(" ")
            ));
            
            if let Some(ref conn) = media.connection {
                result.push_str(&format!("c=IN IP4 {}\r\n", conn.connection_address));
            }
        }
        
        result
    }

    /// Rewrite connection addresses for B2BUA
    pub fn rewrite_connection_addresses(&mut self, new_address: &str) {
        self.origin.unicast_address = new_address.to_string();
        
        if let Some(ref mut conn) = self.connection {
            conn.connection_address = new_address.to_string();
        }
        
        for media in &mut self.media_descriptions {
            if let Some(ref mut conn) = media.connection {
                conn.connection_address = new_address.to_string();
            }
        }
    }

    /// Change media port for B2BUA RTP proxy
    pub fn change_media_port(&mut self, media_index: usize, new_port: u16) {
        if let Some(media) = self.media_descriptions.get_mut(media_index) {
            media.port = new_port;
        }
    }

    /// Extract basic codec information
    pub fn extract_codecs(&self) -> Vec<CodecInfo> {
        let mut codecs = Vec::new();
        
        for media in &self.media_descriptions {
            for format in &media.formats {
                if let Ok(pt) = format.parse::<u8>() {
                    let codec = CodecInfo {
                        payload_type: pt,
                        name: get_codec_name(pt).unwrap_or("unknown").to_string(),
                        clock_rate: get_clock_rate(pt).unwrap_or(8000),
                    };
                    codecs.push(codec);
                }
            }
        }
        
        codecs
    }

    /// Simple codec filtering
    pub fn filter_codecs(&mut self, allowed_codecs: &[&str]) {
        for media in &mut self.media_descriptions {
            media.formats.retain(|format| {
                if let Ok(pt) = format.parse::<u8>() {
                    if let Some(name) = get_codec_name(pt) {
                        return allowed_codecs.iter().any(|&allowed| allowed.eq_ignore_ascii_case(name));
                    }
                }
                false
            });
        }
    }
}

// Helper functions
fn parse_origin(value: &str) -> SsbcResult<Origin> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() < 6 {
        return Err(SsbcError::parse_error("Invalid origin line", None, None));
    }
    
    Ok(Origin {
        username: parts[0].to_string(),
        session_id: parts[1].to_string(),
        session_version: parts[2].to_string(),
        unicast_address: parts[5].to_string(),
    })
}

fn parse_connection(value: &str) -> SsbcResult<Connection> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() < 3 {
        return Err(SsbcError::parse_error("Invalid connection line", None, None));
    }
    
    Ok(Connection {
        connection_address: parts[2].to_string(),
    })
}

fn parse_media_description(value: &str, _lines: &[&str], _index: &mut usize) -> SsbcResult<MediaDescription> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() < 4 {
        return Err(SsbcError::parse_error("Invalid media line", None, None));
    }
    
    let port = parts[1].parse().map_err(|_| {
        SsbcError::parse_error("Invalid port in media line", None, None)
    })?;
    
    let formats = parts[3..].iter().map(|s| s.to_string()).collect();
    
    Ok(MediaDescription {
        media_type: parts[0].to_string(),
        port,
        protocol: parts[2].to_string(),
        formats,
        connection: None,
    })
}

fn get_codec_name(payload_type: u8) -> Option<&'static str> {
    match payload_type {
        0 => Some("PCMU"),
        8 => Some("PCMA"),
        18 => Some("G729"),
        _ => None,
    }
}

fn get_clock_rate(payload_type: u8) -> Option<u32> {
    match payload_type {
        0 | 8 | 18 => Some(8000),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_sdp_parsing() {
        let sdp = "v=0\r\no=- 123 456 IN IP4 192.168.1.1\r\ns=Test\r\nc=IN IP4 192.168.1.1\r\nt=0 0\r\nm=audio 5004 RTP/AVP 0 8\r\n";
        
        let session = SessionDescription::parse(sdp).unwrap();
        assert_eq!(session.origin.unicast_address, "192.168.1.1");
        assert_eq!(session.media_descriptions.len(), 1);
        assert_eq!(session.media_descriptions[0].port, 5004);
    }

    #[test]
    fn test_address_rewriting() {
        let sdp = "v=0\r\no=- 123 456 IN IP4 192.168.1.1\r\ns=Test\r\nc=IN IP4 192.168.1.1\r\nt=0 0\r\nm=audio 5004 RTP/AVP 0 8\r\n";
        
        let mut session = SessionDescription::parse(sdp).unwrap();
        session.rewrite_connection_addresses("10.0.0.1");
        
        assert_eq!(session.origin.unicast_address, "10.0.0.1");
        if let Some(ref conn) = session.connection {
            assert_eq!(conn.connection_address, "10.0.0.1");
        }
    }

    #[test]
    fn test_port_change() {
        let sdp = "v=0\r\no=- 123 456 IN IP4 192.168.1.1\r\ns=Test\r\nt=0 0\r\nm=audio 5004 RTP/AVP 0 8\r\n";
        
        let mut session = SessionDescription::parse(sdp).unwrap();
        session.change_media_port(0, 6000);
        
        assert_eq!(session.media_descriptions[0].port, 6000);
    }
}