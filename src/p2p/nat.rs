//! WAN NAT Traversal and STUN Client (RFC 8489).
//!
//! Discovers the public external IP and mapped UDP port of the local node
//! without requiring central servers or port forwarding.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::{info, warn};

const STUN_MAGIC_COOKIE: u32 = 0x2112A442;
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_RESPONSE: u16 = 0x0101;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;

pub const DEFAULT_STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun.cloudflare.com:3478",
];

/// Queries a STUN server to discover the external public SocketAddr for a local UDP socket.
pub async fn query_stun_external_addr(
    stun_server: &str,
    local_port: u16,
) -> Result<SocketAddr, Box<dyn std::error::Error + Send + Sync>> {
    let local_bind = SocketAddr::from(([0, 0, 0, 0], local_port));
    let socket = UdpSocket::bind(local_bind).await?;
    
    // Resolve STUN server address
    let target_addr: SocketAddr = tokio::net::lookup_host(stun_server)
        .await?
        .next()
        .ok_or_else(|| format!("Could not resolve STUN server: {}", stun_server))?;

    // Build 20-byte STUN Binding Request header
    let mut request = [0u8; 20];
    request[0..2].copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    request[2..4].copy_from_slice(&0u16.to_be_bytes()); // Message Length: 0
    request[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());

    // Generate 12-byte Transaction ID
    let tx_id = uuid::Uuid::new_v4();
    request[8..20].copy_from_slice(&tx_id.as_bytes()[0..12]);

    socket.send_to(&request, target_addr).await?;

    let mut buf = [0u8; 1024];
    let (len, _) = tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut buf)).await??;

    if len < 20 {
        return Err("STUN response too short".into());
    }

    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    let magic = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);

    if msg_type != STUN_BINDING_RESPONSE || magic != STUN_MAGIC_COOKIE {
        return Err("Invalid STUN response header".into());
    }

    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let mut offset = 20;
    let end = (20 + msg_len).min(len);

    while offset + 4 <= end {
        let attr_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let attr_len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
        offset += 4;

        if offset + attr_len > end {
            break;
        }

        if attr_type == ATTR_XOR_MAPPED_ADDRESS && attr_len >= 8 {
            let family = buf[offset + 1];
            if family == 0x01 { // IPv4
                let raw_port = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
                let xor_port = raw_port ^ (STUN_MAGIC_COOKIE >> 16) as u16;

                let raw_ip = u32::from_be_bytes([buf[offset + 4], buf[offset + 5], buf[offset + 6], buf[offset + 7]]);
                let xor_ip = raw_ip ^ STUN_MAGIC_COOKIE;
                let ip = Ipv4Addr::from(xor_ip);

                let resolved = SocketAddr::new(IpAddr::V4(ip), xor_port);
                info!("STUN resolved external mapped address: {}", resolved);
                return Ok(resolved);
            }
        } else if attr_type == ATTR_MAPPED_ADDRESS && attr_len >= 8 {
            let family = buf[offset + 1];
            if family == 0x01 { // IPv4
                let port = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
                let ip = Ipv4Addr::new(buf[offset + 4], buf[offset + 5], buf[offset + 6], buf[offset + 7]);
                let resolved = SocketAddr::new(IpAddr::V4(ip), port);
                return Ok(resolved);
            }
        }

        // Attributes are padded to 4-byte boundaries
        offset += (attr_len + 3) & !3;
    }

    Err("STUN response did not contain mapped address attribute".into())
}

/// Automatically resolves public external IP by querying primary and backup STUN servers.
pub async fn resolve_public_endpoint(p2p_port: u16) -> Option<SocketAddr> {
    for server in DEFAULT_STUN_SERVERS {
        match query_stun_external_addr(server, 0).await {
            Ok(mut addr) => {
                // If local port was mapped or we use p2p_port
                addr.set_port(p2p_port);
                return Some(addr);
            }
            Err(e) => {
                warn!("STUN query to {} failed: {}", server, e);
            }
        }
    }
    None
}
