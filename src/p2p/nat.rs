//! WAN NAT Traversal, STUN Client (RFC 8489), UPnP SSDP Discovery, and NAT-PMP (RFC 6886).
//!
//! Provides automated external address discovery and port mapping across:
//! - STUN RFC 8489 (UDP public endpoint resolution)
//! - UPnP SSDP M-SEARCH multicast discovery (UDP 239.255.255.250:1900)
//! - NAT-PMP (RFC 6886) automated port allocation

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::{info, warn};

// ============================================================================
// STUN Protocol Constants (RFC 8489)
// ============================================================================

pub const STUN_MAGIC_COOKIE: u32 = 0x2112A442;
pub const STUN_BINDING_REQUEST: u16 = 0x0001;
pub const STUN_BINDING_RESPONSE: u16 = 0x0101;
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;

pub const DEFAULT_STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun.cloudflare.com:3478",
];

/// Builds a 20-byte STUN Binding Request packet with the specified 12-byte transaction ID (RFC 8489 Section 5).
pub fn build_stun_binding_request(tx_id: &[u8; 12]) -> [u8; 20] {
    let mut request = [0u8; 20];
    request[0..2].copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    request[2..4].copy_from_slice(&0u16.to_be_bytes()); // Message Length: 0
    request[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    request[8..20].copy_from_slice(tx_id);
    request
}

/// Builds a STUN Binding Response packet with an IPv4 XOR-mapped address or standard mapped address.
pub fn build_stun_binding_response(tx_id: &[u8; 12], mapped_addr: SocketAddr, xor: bool) -> Vec<u8> {
    let mut resp = Vec::with_capacity(32);
    // Header (20 bytes)
    resp.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
    // 1 attribute of 8 bytes payload + 4 byte header = 12 bytes
    resp.extend_from_slice(&12u16.to_be_bytes());
    resp.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    resp.extend_from_slice(tx_id);

    match mapped_addr {
        SocketAddr::V4(v4) => {
            if xor {
                resp.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
                resp.extend_from_slice(&8u16.to_be_bytes());
                resp.push(0x00); // reserved
                resp.push(0x01); // IPv4 family
                let xor_port = v4.port() ^ (STUN_MAGIC_COOKIE >> 16) as u16;
                resp.extend_from_slice(&xor_port.to_be_bytes());
                let raw_ip = u32::from_be_bytes(v4.ip().octets());
                let xor_ip = raw_ip ^ STUN_MAGIC_COOKIE;
                resp.extend_from_slice(&xor_ip.to_be_bytes());
            } else {
                resp.extend_from_slice(&ATTR_MAPPED_ADDRESS.to_be_bytes());
                resp.extend_from_slice(&8u16.to_be_bytes());
                resp.push(0x00); // reserved
                resp.push(0x01); // IPv4 family
                resp.extend_from_slice(&v4.port().to_be_bytes());
                resp.extend_from_slice(&v4.ip().octets());
            }
        }
        SocketAddr::V6(_) => {
            // IPv6 not used in default STUN discovery
        }
    }
    resp
}

/// Parses a STUN response packet and extracts the mapped SocketAddr.
/// Supports both XOR-MAPPED-ADDRESS (RFC 8489 / RFC 5389) and legacy MAPPED-ADDRESS (RFC 3489).
pub fn parse_stun_response(buf: &[u8]) -> Result<SocketAddr, String> {
    let len = buf.len();
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
            if family == 0x01 {
                // IPv4
                let raw_port = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
                let xor_port = raw_port ^ (STUN_MAGIC_COOKIE >> 16) as u16;

                let raw_ip = u32::from_be_bytes([
                    buf[offset + 4],
                    buf[offset + 5],
                    buf[offset + 6],
                    buf[offset + 7],
                ]);
                let xor_ip = raw_ip ^ STUN_MAGIC_COOKIE;
                let ip = Ipv4Addr::from(xor_ip);

                let resolved = SocketAddr::new(IpAddr::V4(ip), xor_port);
                return Ok(resolved);
            }
        } else if attr_type == ATTR_MAPPED_ADDRESS && attr_len >= 8 {
            let family = buf[offset + 1];
            if family == 0x01 {
                // IPv4
                let port = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
                let ip = Ipv4Addr::new(
                    buf[offset + 4],
                    buf[offset + 5],
                    buf[offset + 6],
                    buf[offset + 7],
                );
                let resolved = SocketAddr::new(IpAddr::V4(ip), port);
                return Ok(resolved);
            }
        }

        // Attributes are padded to 4-byte boundaries
        offset = match offset.checked_add((attr_len + 3) & !3) {
            Some(o) => o,
            None => break,
        };
    }

    Err("STUN response did not contain mapped address attribute".into())
}

/// Queries a STUN server to discover the external public SocketAddr for a local UDP socket.
pub async fn query_stun_external_addr(
    stun_server: &str,
    local_port: u16,
) -> Result<SocketAddr, Box<dyn std::error::Error + Send + Sync>> {
    // Resolve STUN server address
    let target_addr: SocketAddr = tokio::net::lookup_host(stun_server)
        .await?
        .next()
        .ok_or_else(|| format!("Could not resolve STUN server: {}", stun_server))?;

    let bind_ip = if target_addr.ip().is_loopback() {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    } else {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    };
    let local_bind = SocketAddr::new(bind_ip, local_port);
    let socket = UdpSocket::bind(local_bind).await?;

    // Build 20-byte STUN Binding Request header
    let tx_uuid = uuid::Uuid::new_v4();
    let mut tx_id = [0u8; 12];
    tx_id.copy_from_slice(&tx_uuid.as_bytes()[0..12]);
    let request = build_stun_binding_request(&tx_id);

    socket.send_to(&request, target_addr).await?;

    let mut buf = [0u8; 1024];
    let (len, _) = tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut buf)).await??;

    let resolved = parse_stun_response(&buf[..len])?;
    info!("STUN resolved external mapped address: {}", resolved);
    Ok(resolved)
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

// ============================================================================
// UPnP SSDP Discovery (RFC 239.255.255.250:1900)
// ============================================================================

pub const SSDP_MULTICAST_IPV4: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
pub const SSDP_PORT: u16 = 1900;
pub const SSDP_MULTICAST_ADDR: &str = "239.255.255.250:1900";

pub const UPNP_ROOT_DEVICE: &str = "upnp:rootdevice";
pub const UPNP_IGD_DEVICE_1: &str = "urn:schemas-upnp-org:device:InternetGatewayDevice:1";
pub const UPNP_IGD_DEVICE_2: &str = "urn:schemas-upnp-org:device:InternetGatewayDevice:2";
pub const UPNP_WAN_IP_CONN_1: &str = "urn:schemas-upnp-org:service:WANIPConnection:1";
pub const UPNP_WAN_PPP_CONN_1: &str = "urn:schemas-upnp-org:service:WANPPPConnection:1";

/// Constructs an RFC-compliant UPnP SSDP M-SEARCH multicast discovery request packet.
pub fn build_ssdp_msearch_request(search_target: &str, mx_seconds: u32) -> String {
    format!(
        "M-SEARCH * HTTP/1.1\r\n\
        HOST: 239.255.255.250:1900\r\n\
        MAN: \"ssdp:discover\"\r\n\
        MX: {}\r\n\
        ST: {}\r\n\
        \r\n",
        mx_seconds, search_target
    )
}

/// Parsed SSDP M-SEARCH discovery request packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsdpSearchRequest {
    pub host: String,
    pub man: String,
    pub mx: u32,
    pub st: String,
    pub headers: HashMap<String, String>,
}

/// Parsed SSDP response packet from an Internet Gateway Device (IGD) or UPnP device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsdpResponse {
    pub status_code: u16,
    pub status_text: String,
    pub location: Option<String>,
    pub server: Option<String>,
    pub st: Option<String>,
    pub usn: Option<String>,
    pub headers: HashMap<String, String>,
}

/// Unified SSDP packet variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsdpPacket {
    SearchRequest(SsdpSearchRequest),
    Response(SsdpResponse),
}

/// Parses an incoming SSDP M-SEARCH HTTP-like multicast request string.
pub fn parse_ssdp_msearch(payload: &str) -> Option<SsdpSearchRequest> {
    let mut lines = payload.lines();
    let mut first_line = "";
    for line in &mut lines {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            first_line = trimmed;
            break;
        }
    }
    if first_line.is_empty() {
        return None;
    }

    // Verify M-SEARCH method
    let mut parts = first_line.split_whitespace();
    let method = parts.next()?;
    if !method.eq_ignore_ascii_case("M-SEARCH") {
        return None;
    }

    let mut headers = HashMap::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some((key, value)) = trimmed.split_once(':') {
            headers.insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    let host = headers.get("host")?.clone();
    let raw_man = headers.get("man")?.clone();
    let man = raw_man.trim_matches('"').to_string();
    let mx_str = headers.get("mx")?;
    let mx: u32 = mx_str.parse().ok()?;
    let st = headers.get("st")?.clone();

    Some(SsdpSearchRequest {
        host,
        man,
        mx,
        st,
        headers,
    })
}

/// Parses an SSDP response string (e.g., `HTTP/1.1 200 OK`) from a UPnP gateway.
pub fn parse_ssdp_response(payload: &str) -> Option<SsdpResponse> {
    let mut lines = payload.lines();
    let mut first_line = "";
    for line in &mut lines {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            first_line = trimmed;
            break;
        }
    }
    if first_line.is_empty() {
        return None;
    }

    // Expect HTTP/1.1 200 OK or similar
    let mut parts = first_line.split_whitespace();
    let http_ver = parts.next()?;
    if !http_ver.to_ascii_uppercase().starts_with("HTTP/") {
        return None;
    }

    let code_str = parts.next()?;
    let status_code: u16 = code_str.parse().ok()?;
    let status_text = parts.collect::<Vec<&str>>().join(" ");

    let mut headers = HashMap::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some((key, value)) = trimmed.split_once(':') {
            headers.insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    let location = headers.get("location").cloned();
    let server = headers.get("server").cloned();
    let st = headers.get("st").cloned();
    let usn = headers.get("usn").cloned();

    Some(SsdpResponse {
        status_code,
        status_text,
        location,
        server,
        st,
        usn,
        headers,
    })
}

/// Parses an arbitrary byte slice as either an SSDP M-SEARCH request or an SSDP response.
pub fn parse_ssdp_packet(data: &[u8]) -> Option<SsdpPacket> {
    let payload = std::str::from_utf8(data).ok()?;
    let trimmed = payload.trim_start();
    if trimmed.to_ascii_uppercase().starts_with("M-SEARCH") {
        parse_ssdp_msearch(payload).map(SsdpPacket::SearchRequest)
    } else if trimmed.to_ascii_uppercase().starts_with("HTTP/") {
        parse_ssdp_response(payload).map(SsdpPacket::Response)
    } else {
        None
    }
}

/// Sends an SSDP M-SEARCH discovery query over UDP multicast (239.255.255.250:1900)
/// with a brief timeout to discover local UPnP IGD gateways.
pub async fn discover_upnp_gateways(
    search_target: &str,
    mx_seconds: u32,
    timeout: Duration,
) -> Result<Vec<SsdpResponse>, Box<dyn std::error::Error + Send + Sync>> {
    let local_bind = SocketAddr::from(([0, 0, 0, 0], 0));
    let socket = UdpSocket::bind(local_bind).await?;
    let _ = socket.set_broadcast(true);

    let msearch_req = build_ssdp_msearch_request(search_target, mx_seconds);
    let target_addr: SocketAddr = SSDP_MULTICAST_ADDR.parse()?;

    socket.send_to(msearch_req.as_bytes(), target_addr).await?;

    let mut responses = Vec::new();
    let mut buf = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + timeout;

    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _sender))) => {
                if let Some(resp) = parse_ssdp_packet(&buf[..len]) {
                    if let SsdpPacket::Response(r) = resp {
                        responses.push(r);
                    }
                }
            }
            _ => break,
        }
    }

    Ok(responses)
}

// ============================================================================
// NAT-PMP Protocol (RFC 6886)
// ============================================================================

pub const NAT_PMP_PORT: u16 = 5351;
pub const NAT_PMP_VERSION: u8 = 0;
pub const NAT_PMP_OP_EXTERNAL_IP: u8 = 0;
pub const NAT_PMP_OP_MAP_UDP: u8 = 1;
pub const NAT_PMP_OP_MAP_TCP: u8 = 2;
pub const NAT_PMP_DEFAULT_LIFETIME: u32 = 7200; // 2 hours

/// Transport protocol for NAT-PMP port mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatPmpProtocol {
    Udp = 1,
    Tcp = 2,
}

/// NAT-PMP response result codes according to RFC 6886.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatPmpResultCode {
    Success,
    UnsupportedVersion,
    NotAuthorized,
    NetworkFailure,
    OutOfResources,
    UnsupportedOpcode,
    Unknown(u16),
}

impl NatPmpResultCode {
    pub fn is_success(&self) -> bool {
        matches!(self, NatPmpResultCode::Success)
    }

    pub fn code(&self) -> u16 {
        match self {
            NatPmpResultCode::Success => 0,
            NatPmpResultCode::UnsupportedVersion => 1,
            NatPmpResultCode::NotAuthorized => 2,
            NatPmpResultCode::NetworkFailure => 3,
            NatPmpResultCode::OutOfResources => 4,
            NatPmpResultCode::UnsupportedOpcode => 5,
            NatPmpResultCode::Unknown(c) => *c,
        }
    }
}

/// Generates a 12-byte NAT-PMP port mapping request packet (RFC 6886 Section 3.3).
///
/// Packet Layout:
/// - Byte 0: Version (0)
/// - Byte 1: OP (1 for UDP, 2 for TCP)
/// - Bytes 2..4: Reserved (0x0000)
/// - Bytes 4..6: Internal Port (u16 big-endian)
/// - Bytes 6..8: Suggested External Port (u16 big-endian)
/// - Bytes 8..12: Requested Lifetime in Seconds (u32 big-endian)
pub fn generate_nat_pmp_port_request(
    protocol: NatPmpProtocol,
    internal_port: u16,
    suggested_external_port: u16,
    lifetime_secs: u32,
) -> [u8; 12] {
    let mut pkt = [0u8; 12];
    pkt[0] = NAT_PMP_VERSION;
    pkt[1] = protocol as u8;
    pkt[2] = 0; // Reserved
    pkt[3] = 0; // Reserved
    pkt[4..6].copy_from_slice(&internal_port.to_be_bytes());
    pkt[6..8].copy_from_slice(&suggested_external_port.to_be_bytes());
    pkt[8..12].copy_from_slice(&lifetime_secs.to_be_bytes());
    pkt
}

/// Generates a 12-byte NAT-PMP mapping deletion request (lifetime = 0).
pub fn generate_nat_pmp_port_deletion(
    protocol: NatPmpProtocol,
    internal_port: u16,
) -> [u8; 12] {
    generate_nat_pmp_port_request(protocol, internal_port, 0, 0)
}

/// Generates a 2-byte NAT-PMP external IP address request packet (RFC 6886 Section 3.2).
pub fn generate_nat_pmp_external_address_request() -> [u8; 2] {
    [NAT_PMP_VERSION, NAT_PMP_OP_EXTERNAL_IP]
}

/// Parsed NAT-PMP port mapping response (16 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatPmpMappingResponse {
    pub protocol: NatPmpProtocol,
    pub result_code: NatPmpResultCode,
    pub raw_result_code: u16,
    pub epoch_seconds: u32,
    pub internal_port: u16,
    pub mapped_external_port: u16,
    pub lifetime_seconds: u32,
}

/// Parsed NAT-PMP external address response (12 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatPmpAddressResponse {
    pub result_code: NatPmpResultCode,
    pub raw_result_code: u16,
    pub epoch_seconds: u32,
    pub external_ip: Ipv4Addr,
}

/// Parses a 16-byte NAT-PMP port mapping response packet.
pub fn parse_nat_pmp_mapping_response(bytes: &[u8]) -> Result<NatPmpMappingResponse, String> {
    if bytes.len() < 16 {
        return Err(format!(
            "NAT-PMP mapping response too short: expected 16 bytes, got {}",
            bytes.len()
        ));
    }
    if bytes[0] != NAT_PMP_VERSION {
        return Err(format!("Unsupported NAT-PMP version: {}", bytes[0]));
    }
    let op = bytes[1];
    let protocol = match op {
        129 => NatPmpProtocol::Udp,
        130 => NatPmpProtocol::Tcp,
        _ => return Err(format!("Unexpected OP code in NAT-PMP mapping response: {}", op)),
    };

    let raw_result_code = u16::from_be_bytes([bytes[2], bytes[3]]);
    let result_code = match raw_result_code {
        0 => NatPmpResultCode::Success,
        1 => NatPmpResultCode::UnsupportedVersion,
        2 => NatPmpResultCode::NotAuthorized,
        3 => NatPmpResultCode::NetworkFailure,
        4 => NatPmpResultCode::OutOfResources,
        5 => NatPmpResultCode::UnsupportedOpcode,
        code => NatPmpResultCode::Unknown(code),
    };

    let epoch_seconds = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let internal_port = u16::from_be_bytes([bytes[8], bytes[9]]);
    let mapped_external_port = u16::from_be_bytes([bytes[10], bytes[11]]);
    let lifetime_seconds = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);

    Ok(NatPmpMappingResponse {
        protocol,
        result_code,
        raw_result_code,
        epoch_seconds,
        internal_port,
        mapped_external_port,
        lifetime_seconds,
    })
}

/// Parses a 12-byte NAT-PMP external address response packet.
pub fn parse_nat_pmp_address_response(bytes: &[u8]) -> Result<NatPmpAddressResponse, String> {
    if bytes.len() < 12 {
        return Err(format!(
            "NAT-PMP address response too short: expected 12 bytes, got {}",
            bytes.len()
        ));
    }
    if bytes[0] != NAT_PMP_VERSION {
        return Err(format!("Unsupported NAT-PMP version: {}", bytes[0]));
    }
    if bytes[1] != 128 {
        return Err(format!("Unexpected OP code in NAT-PMP address response: {}", bytes[1]));
    }

    let raw_result_code = u16::from_be_bytes([bytes[2], bytes[3]]);
    let result_code = match raw_result_code {
        0 => NatPmpResultCode::Success,
        1 => NatPmpResultCode::UnsupportedVersion,
        2 => NatPmpResultCode::NotAuthorized,
        3 => NatPmpResultCode::NetworkFailure,
        4 => NatPmpResultCode::OutOfResources,
        5 => NatPmpResultCode::UnsupportedOpcode,
        code => NatPmpResultCode::Unknown(code),
    };

    let epoch_seconds = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let external_ip = Ipv4Addr::new(bytes[8], bytes[9], bytes[10], bytes[11]);

    Ok(NatPmpAddressResponse {
        result_code,
        raw_result_code,
        epoch_seconds,
        external_ip,
    })
}

/// Asynchronously requests a port mapping from a default gateway over NAT-PMP.
pub async fn request_nat_pmp_port_mapping(
    gateway_ip: Ipv4Addr,
    protocol: NatPmpProtocol,
    internal_port: u16,
    suggested_external_port: u16,
    lifetime_secs: u32,
    timeout: Duration,
) -> Result<NatPmpMappingResponse, Box<dyn std::error::Error + Send + Sync>> {
    let target_addr = SocketAddr::new(IpAddr::V4(gateway_ip), NAT_PMP_PORT);
    let socket = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0))).await?;

    let packet = generate_nat_pmp_port_request(
        protocol,
        internal_port,
        suggested_external_port,
        lifetime_secs,
    );

    socket.send_to(&packet, target_addr).await?;

    let mut buf = [0u8; 64];
    let (len, _) = tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await??;
    let response = parse_nat_pmp_mapping_response(&buf[..len])?;
    Ok(response)
}

// ============================================================================
// Unit and Stress Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // 1. RFC 8489 STUN Unit & Stress Tests
    // ========================================================================

    #[test]
    fn test_stun_binding_request_structure() {
        let tx_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let req = build_stun_binding_request(&tx_id);
        assert_eq!(req.len(), 20);
        assert_eq!(u16::from_be_bytes([req[0], req[1]]), STUN_BINDING_REQUEST);
        assert_eq!(u16::from_be_bytes([req[2], req[3]]), 0); // message length: 0
        assert_eq!(u32::from_be_bytes([req[4], req[5], req[6], req[7]]), STUN_MAGIC_COOKIE);
        assert_eq!(&req[8..20], &tx_id);
    }

    #[test]
    fn test_stun_ipv4_xor_mapped_parsing() {
        let tx_id = [42u8; 12];
        let test_addrs = [
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42)), 54321),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)), 65535),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40)), 9190),
        ];

        for &addr in &test_addrs {
            let resp_bytes = build_stun_binding_response(&tx_id, addr, true);
            let parsed = parse_stun_response(&resp_bytes).expect("Failed to parse XOR-mapped STUN response");
            assert_eq!(parsed, addr);
        }
    }

    #[test]
    fn test_stun_ipv4_standard_mapped_parsing() {
        let tx_id = [99u8; 12];
        let test_addrs = [
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 8080),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 16, 1, 5)), 3478),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
        ];

        for &addr in &test_addrs {
            let resp_bytes = build_stun_binding_response(&tx_id, addr, false);
            let parsed = parse_stun_response(&resp_bytes).expect("Failed to parse standard mapped STUN response");
            assert_eq!(parsed, addr);
        }
    }

    #[test]
    fn test_stun_response_multiple_attributes_and_padding() {
        let tx_id = [7u8; 12];
        let mapped = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 195)), 12345);

        // Prepend an unknown attribute (e.g. SOFTWARE = "Synapse") before XOR_MAPPED_ADDRESS
        // "Synapse" is 7 bytes -> requires 1 byte padding to align to 4 bytes
        let mut resp = Vec::new();
        resp.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        // Length: (4 + 8) software attr + (4 + 8) xor attr = 24 bytes
        resp.extend_from_slice(&24u16.to_be_bytes());
        resp.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        resp.extend_from_slice(&tx_id);

        // Software attribute: type 0x8022, len 7
        resp.extend_from_slice(&0x8022u16.to_be_bytes());
        resp.extend_from_slice(&7u16.to_be_bytes());
        resp.extend_from_slice(b"Synapse");
        resp.push(0x00); // 1 byte padding to 8 bytes

        // XOR-MAPPED-ADDRESS
        resp.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        resp.extend_from_slice(&8u16.to_be_bytes());
        resp.push(0x00);
        resp.push(0x01);
        let xor_port = mapped.port() ^ (STUN_MAGIC_COOKIE >> 16) as u16;
        resp.extend_from_slice(&xor_port.to_be_bytes());
        let raw_ip = match mapped.ip() {
            IpAddr::V4(v4) => u32::from_be_bytes(v4.octets()),
            _ => unreachable!(),
        };
        resp.extend_from_slice(&(raw_ip ^ STUN_MAGIC_COOKIE).to_be_bytes());

        let parsed = parse_stun_response(&resp).expect("Failed to parse response with multiple attributes");
        assert_eq!(parsed, mapped);
    }

    #[test]
    fn test_stun_response_malformed_headers() {
        // Empty buffer
        assert!(parse_stun_response(&[]).is_err());

        // Truncated headers (< 20 bytes)
        assert!(parse_stun_response(&[0u8; 1]).is_err());
        assert!(parse_stun_response(&[0u8; 10]).is_err());
        assert!(parse_stun_response(&[0u8; 19]).is_err());

        // Wrong message type (e.g., STUN_BINDING_REQUEST 0x0001 instead of 0x0101)
        let mut invalid_type = [0u8; 20];
        invalid_type[0..2].copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
        invalid_type[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        assert!(parse_stun_response(&invalid_type).is_err());

        // Error response 0x0111
        let mut err_resp = [0u8; 20];
        err_resp[0..2].copy_from_slice(&0x0111u16.to_be_bytes());
        err_resp[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        assert!(parse_stun_response(&err_resp).is_err());

        // Wrong magic cookie
        let mut invalid_cookie = [0u8; 20];
        invalid_cookie[0..2].copy_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        invalid_cookie[4..8].copy_from_slice(&0x12345678u32.to_be_bytes());
        assert!(parse_stun_response(&invalid_cookie).is_err());

        // Truncated attribute header (< 4 bytes for attribute)
        let mut trunc_attr = [0u8; 22];
        trunc_attr[0..2].copy_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        trunc_attr[2..4].copy_from_slice(&2u16.to_be_bytes()); // length 2
        trunc_attr[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        assert!(parse_stun_response(&trunc_attr).is_err());

        // Attribute length exceeds buffer bounds
        let mut overflow_attr = [0u8; 28];
        overflow_attr[0..2].copy_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        overflow_attr[2..4].copy_from_slice(&8u16.to_be_bytes());
        overflow_attr[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        overflow_attr[20..22].copy_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        overflow_attr[22..24].copy_from_slice(&100u16.to_be_bytes()); // claimed 100 bytes
        assert!(parse_stun_response(&overflow_attr).is_err());

        // Valid header but no mapped address attribute
        let mut no_mapped = [0u8; 20];
        no_mapped[0..2].copy_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        no_mapped[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        assert!(parse_stun_response(&no_mapped).is_err());

        // Unsupported family in XOR-MAPPED-ADDRESS (e.g. 0x02 for IPv6)
        let mut ipv6_mapped = [0u8; 32];
        ipv6_mapped[0..2].copy_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        ipv6_mapped[2..4].copy_from_slice(&12u16.to_be_bytes());
        ipv6_mapped[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        ipv6_mapped[20..22].copy_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        ipv6_mapped[22..24].copy_from_slice(&8u16.to_be_bytes());
        ipv6_mapped[24] = 0x00;
        ipv6_mapped[25] = 0x02; // IPv6 family
        assert!(parse_stun_response(&ipv6_mapped).is_err());
    }

    #[test]
    fn test_stun_fuzz_garbage_resilience() {
        use rand::RngCore;
        let mut rng = rand::rngs::OsRng;
        for _ in 0..500 {
            let len = (rng.next_u32() % 256) as usize;
            let mut buf = vec![0u8; len];
            rng.fill_bytes(&mut buf);
            // Parser must never panic on arbitrary input
            let _ = parse_stun_response(&buf);
        }
    }

    #[tokio::test]
    async fn test_stun_local_mock_server_e2e() {
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.expect("Bind mock STUN server");
        let server_addr = server_socket.local_addr().unwrap();

        let mock_server_handle = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let (len, client_addr) = server_socket.recv_from(&mut buf).await.unwrap();
            assert!(len >= 20);
            assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), STUN_BINDING_REQUEST);
            assert_eq!(u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]), STUN_MAGIC_COOKIE);

            let mut tx_id = [0u8; 12];
            tx_id.copy_from_slice(&buf[8..20]);

            let mapped_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77)), 45678);
            let resp = build_stun_binding_response(&tx_id, mapped_addr, true);
            server_socket.send_to(&resp, client_addr).await.unwrap();
        });

        match query_stun_external_addr(&server_addr.to_string(), 0).await {
            Ok(resolved) => {
                assert_eq!(resolved, SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77)), 45678));
            }
            Err(e) if e.to_string().contains("Network is unreachable") => {
                // In sandboxed environments without loopback routing, skip network I/O
                return;
            }
            Err(e) => panic!("Query mock STUN failed: {}", e),
        }

        let _ = mock_server_handle.await;
    }

    // ========================================================================
    // 2. UPnP SSDP Discovery Unit & Stress Tests
    // ========================================================================

    #[test]
    fn test_ssdp_msearch_request_formatting() {
        let req = build_ssdp_msearch_request(UPNP_IGD_DEVICE_1, 2);
        assert!(req.starts_with("M-SEARCH * HTTP/1.1\r\n"));
        assert!(req.contains("HOST: 239.255.255.250:1900\r\n"));
        assert!(req.contains("MAN: \"ssdp:discover\"\r\n"));
        assert!(req.contains("MX: 2\r\n"));
        assert!(req.contains(&format!("ST: {}\r\n", UPNP_IGD_DEVICE_1)));
        assert!(req.ends_with("\r\n\r\n"));
    }

    #[test]
    fn test_ssdp_msearch_formatting_variations() {
        let targets = [
            UPNP_ROOT_DEVICE,
            UPNP_IGD_DEVICE_1,
            UPNP_IGD_DEVICE_2,
            UPNP_WAN_IP_CONN_1,
            UPNP_WAN_PPP_CONN_1,
            "ssdp:all",
        ];

        for target in targets {
            for mx in [1, 2, 5, 120] {
                let req = build_ssdp_msearch_request(target, mx);
                assert!(req.starts_with("M-SEARCH * HTTP/1.1\r\n"));
                assert!(req.contains("HOST: 239.255.255.250:1900\r\n"));
                assert!(req.contains("MAN: \"ssdp:discover\"\r\n"));
                assert!(req.contains(&format!("MX: {}\r\n", mx)));
                assert!(req.contains(&format!("ST: {}\r\n", target)));
                assert!(req.ends_with("\r\n\r\n"));

                // Round-trip parse
                let parsed = parse_ssdp_msearch(&req).expect("Failed to parse generated M-SEARCH");
                assert_eq!(parsed.host, "239.255.255.250:1900");
                assert_eq!(parsed.man, "ssdp:discover");
                assert_eq!(parsed.mx, mx);
                assert_eq!(parsed.st, target);
            }
        }
    }

    #[test]
    fn test_parse_ssdp_msearch_request() {
        let raw = "M-SEARCH * HTTP/1.1\r\n\
                   HOST: 239.255.255.250:1900\r\n\
                   MAN: \"ssdp:discover\"\r\n\
                   MX: 3\r\n\
                   ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
                   \r\n";

        let parsed = parse_ssdp_msearch(raw).expect("Failed to parse valid M-SEARCH");
        assert_eq!(parsed.host, "239.255.255.250:1900");
        assert_eq!(parsed.man, "ssdp:discover");
        assert_eq!(parsed.mx, 3);
        assert_eq!(parsed.st, "urn:schemas-upnp-org:device:InternetGatewayDevice:1");
    }

    #[test]
    fn test_ssdp_msearch_case_insensitivity_and_whitespace() {
        let raw = "\r\n  \r\nm-search * http/1.1\r\n\
                   hOsT:   239.255.255.250:1900  \r\n\
                   Man: \"ssdp:discover\"\r\n\
                   mX: \t 4 \r\n\
                   St: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
                   \r\n";

        let parsed = parse_ssdp_msearch(raw).expect("Failed to parse case-insensitive M-SEARCH");
        assert_eq!(parsed.host, "239.255.255.250:1900");
        assert_eq!(parsed.man, "ssdp:discover");
        assert_eq!(parsed.mx, 4);
        assert_eq!(parsed.st, "urn:schemas-upnp-org:device:InternetGatewayDevice:1");
    }

    #[test]
    fn test_ssdp_msearch_unquoted_man_and_extra_headers() {
        let raw = "M-SEARCH * HTTP/1.1\r\n\
                   ST: upnp:rootdevice\r\n\
                   MX: 2\r\n\
                   MAN: ssdp:discover\r\n\
                   HOST: 239.255.255.250:1900\r\n\
                   USER-AGENT: SynapseCore/1.0 UPnP/1.1\r\n\
                   BOOTID.UPNP.ORG: 42\r\n\
                   CONFIGID.UPNP.ORG: 1337\r\n\
                   SEARCHPORT.UPNP.ORG: 1900\r\n\
                   \r\n";

        let parsed = parse_ssdp_msearch(raw).expect("Failed to parse M-SEARCH with extra headers");
        assert_eq!(parsed.host, "239.255.255.250:1900");
        assert_eq!(parsed.man, "ssdp:discover");
        assert_eq!(parsed.mx, 2);
        assert_eq!(parsed.st, "upnp:rootdevice");
        assert_eq!(parsed.headers.get("bootid.upnp.org").map(|s| s.as_str()), Some("42"));
        assert_eq!(parsed.headers.get("configid.upnp.org").map(|s| s.as_str()), Some("1337"));
        assert_eq!(parsed.headers.get("searchport.upnp.org").map(|s| s.as_str()), Some("1900"));
    }

    #[test]
    fn test_ssdp_msearch_malformed_variations() {
        // Missing HOST
        let no_host = "M-SEARCH * HTTP/1.1\r\nMAN: \"ssdp:discover\"\r\nMX: 3\r\nST: upnp:rootdevice\r\n\r\n";
        assert!(parse_ssdp_msearch(no_host).is_none());

        // Missing MAN
        let no_man = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMX: 3\r\nST: upnp:rootdevice\r\n\r\n";
        assert!(parse_ssdp_msearch(no_man).is_none());

        // Missing MX
        let no_mx = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nST: upnp:rootdevice\r\n\r\n";
        assert!(parse_ssdp_msearch(no_mx).is_none());

        // Non-numeric MX
        let bad_mx = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: invalid\r\nST: upnp:rootdevice\r\n\r\n";
        assert!(parse_ssdp_msearch(bad_mx).is_none());

        // Negative MX
        let neg_mx = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: -5\r\nST: upnp:rootdevice\r\n\r\n";
        assert!(parse_ssdp_msearch(neg_mx).is_none());

        // Missing ST
        let no_st = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 3\r\n\r\n";
        assert!(parse_ssdp_msearch(no_st).is_none());

        // Different HTTP method
        let not_msearch = "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\r\n";
        assert!(parse_ssdp_msearch(not_msearch).is_none());

        // Empty string
        assert!(parse_ssdp_msearch("").is_none());
        assert!(parse_ssdp_msearch("   \r\n\r\n").is_none());
    }

    #[test]
    fn test_parse_ssdp_response() {
        let raw = "HTTP/1.1 200 OK\r\n\
                   LOCATION: http://192.168.1.1:1900/rootDesc.xml\r\n\
                   SERVER: Linux/3.10 UPnP/1.0 MiniUPnPd/2.2.1\r\n\
                   ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
                   USN: uuid:12345678-abcd-ef01-2345-6789abcdef01::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
                   \r\n";

        let resp = parse_ssdp_response(raw).expect("Failed to parse SSDP response");
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.status_text, "OK");
        assert_eq!(
            resp.location.as_deref(),
            Some("http://192.168.1.1:1900/rootDesc.xml")
        );
        assert_eq!(
            resp.server.as_deref(),
            Some("Linux/3.10 UPnP/1.0 MiniUPnPd/2.2.1")
        );
        assert_eq!(
            resp.st.as_deref(),
            Some("urn:schemas-upnp-org:device:InternetGatewayDevice:1")
        );
        assert!(resp.usn.is_some());
    }

    #[test]
    fn test_ssdp_response_variations() {
        // HTTP/1.0 200 OK
        let raw10 = "HTTP/1.0 200 OK\r\n\
                     LOCATION: http://192.168.1.1:80/rootDesc.xml\r\n\
                     SERVER: Linux/4.14 UPnP/1.0 OpenWrt\r\n\
                     ST: upnp:rootdevice\r\n\
                     USN: uuid:abcdef12-3456-7890-abcd-ef1234567890::upnp:rootdevice\r\n\r\n";
        let r10 = parse_ssdp_response(raw10).expect("Failed to parse HTTP/1.0 response");
        assert_eq!(r10.status_code, 200);
        assert_eq!(r10.status_text, "OK");
        assert_eq!(r10.location.as_deref(), Some("http://192.168.1.1:80/rootDesc.xml"));
        assert_eq!(r10.server.as_deref(), Some("Linux/4.14 UPnP/1.0 OpenWrt"));
        assert_eq!(r10.st.as_deref(), Some("upnp:rootdevice"));
        assert!(r10.usn.is_some());

        // Status 200 without status text
        let raw_no_text = "HTTP/1.1 200\r\nLOCATION: http://10.0.0.1:49152/desc.xml\r\n\r\n";
        let r_nt = parse_ssdp_response(raw_no_text).expect("Failed to parse 200 without text");
        assert_eq!(r_nt.status_code, 200);
        assert_eq!(r_nt.status_text, "");
        assert_eq!(r_nt.location.as_deref(), Some("http://10.0.0.1:49152/desc.xml"));
        assert!(r_nt.server.is_none());

        // Status 404
        let raw_404 = "HTTP/1.1 404 Not Found\r\n\r\n";
        let r404 = parse_ssdp_response(raw_404).expect("Failed to parse 404 response");
        assert_eq!(r404.status_code, 404);
        assert_eq!(r404.status_text, "Not Found");

        // Leading blank lines
        let raw_leading = "\r\n\r\nHTTP/1.1 200 OK\r\nLOCATION: http://192.168.0.1:1900/igd.xml\r\n\r\n";
        let r_lead = parse_ssdp_response(raw_leading).expect("Failed to parse with leading blanks");
        assert_eq!(r_lead.status_code, 200);
    }

    #[test]
    fn test_ssdp_response_malformed() {
        assert!(parse_ssdp_response("NOT-HTTP 200 OK\r\n\r\n").is_none());
        assert!(parse_ssdp_response("HTTP/1.1 ABC OK\r\n\r\n").is_none());
        assert!(parse_ssdp_response("HTTP/1.1\r\n\r\n").is_none());
        assert!(parse_ssdp_response("").is_none());
    }

    #[test]
    fn test_parse_ssdp_packet_both_variants() {
        let msearch_data = build_ssdp_msearch_request("ssdp:all", 1);
        let pkt1 = parse_ssdp_packet(msearch_data.as_bytes()).expect("Must parse M-SEARCH");
        assert!(matches!(pkt1, SsdpPacket::SearchRequest(_)));

        let response_data = "HTTP/1.1 200 OK\r\nLOCATION: http://10.0.0.1:80/desc.xml\r\n\r\n";
        let pkt2 = parse_ssdp_packet(response_data.as_bytes()).expect("Must parse Response");
        if let SsdpPacket::Response(r) = pkt2 {
            assert_eq!(r.location.as_deref(), Some("http://10.0.0.1:80/desc.xml"));
        } else {
            panic!("Expected Response variant");
        }
    }

    #[test]
    fn test_ssdp_malformed_packets() {
        assert!(parse_ssdp_msearch("NOT-AN-MSEARCH").is_none());
        assert!(parse_ssdp_response("NOT-HTTP").is_none());
        assert!(parse_ssdp_packet(b"INVALID JUNK DATA").is_none());
    }

    #[test]
    fn test_ssdp_parser_fuzz_garbage() {
        use rand::RngCore;
        let mut rng = rand::rngs::OsRng;
        for _ in 0..500 {
            let len = (rng.next_u32() % 256) as usize;
            let mut buf = vec![0u8; len];
            rng.fill_bytes(&mut buf);
            let _ = parse_ssdp_packet(&buf);
            if let Ok(s) = std::str::from_utf8(&buf) {
                let _ = parse_ssdp_msearch(s);
                let _ = parse_ssdp_response(s);
            }
        }
    }

    // ========================================================================
    // 3. NAT-PMP Protocol Unit & Stress Tests
    // ========================================================================

    #[test]
    fn test_nat_pmp_port_request_generation() {
        let req_udp = generate_nat_pmp_port_request(NatPmpProtocol::Udp, 9190, 9190, 7200);
        assert_eq!(req_udp.len(), 12);
        assert_eq!(req_udp[0], 0); // Version 0
        assert_eq!(req_udp[1], 1); // OP 1 (UDP)
        assert_eq!(req_udp[2], 0); // Reserved
        assert_eq!(req_udp[3], 0); // Reserved
        assert_eq!(u16::from_be_bytes([req_udp[4], req_udp[5]]), 9190);
        assert_eq!(u16::from_be_bytes([req_udp[6], req_udp[7]]), 9190);
        assert_eq!(u32::from_be_bytes([req_udp[8], req_udp[9], req_udp[10], req_udp[11]]), 7200);

        let req_tcp = generate_nat_pmp_port_request(NatPmpProtocol::Tcp, 8080, 0, 3600);
        assert_eq!(req_tcp[1], 2); // OP 2 (TCP)
        assert_eq!(u16::from_be_bytes([req_tcp[4], req_tcp[5]]), 8080);
        assert_eq!(u16::from_be_bytes([req_tcp[6], req_tcp[7]]), 0);
        assert_eq!(u32::from_be_bytes([req_tcp[8], req_tcp[9], req_tcp[10], req_tcp[11]]), 3600);
    }

    #[test]
    fn test_nat_pmp_request_generation_exhaustive() {
        let protocols = [NatPmpProtocol::Udp, NatPmpProtocol::Tcp];
        let internal_ports = [0u16, 1, 80, 443, 9190, 65535];
        let external_ports = [0u16, 80, 9190, 65535];
        let lifetimes = [0u32, 1, 60, 3600, 7200, u32::MAX];

        for &proto in &protocols {
            for &int_p in &internal_ports {
                for &ext_p in &external_ports {
                    for &life in &lifetimes {
                        let pkt = generate_nat_pmp_port_request(proto, int_p, ext_p, life);
                        assert_eq!(pkt.len(), 12);
                        assert_eq!(pkt[0], NAT_PMP_VERSION);
                        assert_eq!(pkt[1], proto as u8);
                        assert_eq!(pkt[2], 0);
                        assert_eq!(pkt[3], 0);
                        assert_eq!(u16::from_be_bytes([pkt[4], pkt[5]]), int_p);
                        assert_eq!(u16::from_be_bytes([pkt[6], pkt[7]]), ext_p);
                        assert_eq!(u32::from_be_bytes([pkt[8], pkt[9], pkt[10], pkt[11]]), life);
                    }
                }
            }
        }
    }

    #[test]
    fn test_nat_pmp_port_deletion_generation() {
        let del = generate_nat_pmp_port_deletion(NatPmpProtocol::Udp, 9190);
        assert_eq!(del[0], 0);
        assert_eq!(del[1], 1);
        assert_eq!(u16::from_be_bytes([del[4], del[5]]), 9190);
        assert_eq!(u16::from_be_bytes([del[6], del[7]]), 0);
        assert_eq!(u32::from_be_bytes([del[8], del[9], del[10], del[11]]), 0);
    }

    #[test]
    fn test_nat_pmp_port_deletion_exhaustive() {
        for proto in [NatPmpProtocol::Udp, NatPmpProtocol::Tcp] {
            for port in [1, 9190, 65535] {
                let del = generate_nat_pmp_port_deletion(proto, port);
                assert_eq!(del.len(), 12);
                assert_eq!(del[0], 0);
                assert_eq!(del[1], proto as u8);
                assert_eq!(u16::from_be_bytes([del[4], del[5]]), port);
                assert_eq!(u16::from_be_bytes([del[6], del[7]]), 0);
                assert_eq!(u32::from_be_bytes([del[8], del[9], del[10], del[11]]), 0);
            }
        }
    }

    #[test]
    fn test_nat_pmp_external_address_request() {
        let req = generate_nat_pmp_external_address_request();
        assert_eq!(req, [0x00, 0x00]);
        assert_eq!(req.len(), 2);
    }

    #[test]
    fn test_nat_pmp_mapping_response_parsing() {
        let mut resp = [0u8; 16];
        resp[0] = 0; // Version 0
        resp[1] = 129; // OP 129 (UDP mapping response)
        resp[2..4].copy_from_slice(&0u16.to_be_bytes()); // Success
        resp[4..8].copy_from_slice(&123456u32.to_be_bytes()); // Epoch
        resp[8..10].copy_from_slice(&9190u16.to_be_bytes()); // Internal port
        resp[10..12].copy_from_slice(&9190u16.to_be_bytes()); // External port
        resp[12..16].copy_from_slice(&7200u32.to_be_bytes()); // Lifetime

        let parsed = parse_nat_pmp_mapping_response(&resp).expect("Failed to parse valid response");
        assert_eq!(parsed.protocol, NatPmpProtocol::Udp);
        assert_eq!(parsed.result_code, NatPmpResultCode::Success);
        assert!(parsed.result_code.is_success());
        assert_eq!(parsed.epoch_seconds, 123456);
        assert_eq!(parsed.internal_port, 9190);
        assert_eq!(parsed.mapped_external_port, 9190);
        assert_eq!(parsed.lifetime_seconds, 7200);
    }

    #[test]
    fn test_nat_pmp_mapping_response_error_codes() {
        let mut resp = [0u8; 16];
        resp[0] = 0;
        resp[1] = 130; // TCP mapping response
        resp[2..4].copy_from_slice(&2u16.to_be_bytes()); // Not Authorized
        let parsed = parse_nat_pmp_mapping_response(&resp).unwrap();
        assert_eq!(parsed.protocol, NatPmpProtocol::Tcp);
        assert_eq!(parsed.result_code, NatPmpResultCode::NotAuthorized);
        assert!(!parsed.result_code.is_success());
    }

    #[test]
    fn test_nat_pmp_mapping_response_all_result_codes() {
        let test_cases = [
            (0u16, NatPmpResultCode::Success, true),
            (1u16, NatPmpResultCode::UnsupportedVersion, false),
            (2u16, NatPmpResultCode::NotAuthorized, false),
            (3u16, NatPmpResultCode::NetworkFailure, false),
            (4u16, NatPmpResultCode::OutOfResources, false),
            (5u16, NatPmpResultCode::UnsupportedOpcode, false),
            (6u16, NatPmpResultCode::Unknown(6), false),
            (99u16, NatPmpResultCode::Unknown(99), false),
            (65535u16, NatPmpResultCode::Unknown(65535), false),
        ];

        for (code, expected_variant, expected_success) in test_cases {
            let mut resp = [0u8; 16];
            resp[0] = 0; // Version
            resp[1] = 129; // OP UDP response
            resp[2..4].copy_from_slice(&code.to_be_bytes());
            resp[4..8].copy_from_slice(&100_000u32.to_be_bytes()); // Epoch
            resp[8..10].copy_from_slice(&9190u16.to_be_bytes()); // Internal port
            resp[10..12].copy_from_slice(&9190u16.to_be_bytes()); // External port
            resp[12..16].copy_from_slice(&7200u32.to_be_bytes()); // Lifetime

            let parsed = parse_nat_pmp_mapping_response(&resp).expect("Failed to parse mapping response");
            assert_eq!(parsed.protocol, NatPmpProtocol::Udp);
            assert_eq!(parsed.result_code, expected_variant);
            assert_eq!(parsed.raw_result_code, code);
            assert_eq!(parsed.result_code.is_success(), expected_success);
            assert_eq!(parsed.result_code.code(), code);
            assert_eq!(parsed.epoch_seconds, 100_000);
            assert_eq!(parsed.internal_port, 9190);
            assert_eq!(parsed.mapped_external_port, 9190);
            assert_eq!(parsed.lifetime_seconds, 7200);
        }
    }

    #[test]
    fn test_nat_pmp_mapping_response_malformed() {
        // Truncated responses
        assert!(parse_nat_pmp_mapping_response(&[]).is_err());
        assert!(parse_nat_pmp_mapping_response(&[0u8; 1]).is_err());
        assert!(parse_nat_pmp_mapping_response(&[0u8; 8]).is_err());
        assert!(parse_nat_pmp_mapping_response(&[0u8; 15]).is_err());

        // Unsupported version
        let mut bad_ver = [0u8; 16];
        bad_ver[0] = 1;
        bad_ver[1] = 129;
        assert!(parse_nat_pmp_mapping_response(&bad_ver).is_err());

        // Unexpected OP codes
        for op in [0, 1, 2, 128, 131, 255] {
            let mut bad_op = [0u8; 16];
            bad_op[0] = 0;
            bad_op[1] = op;
            assert!(parse_nat_pmp_mapping_response(&bad_op).is_err());
        }

        // Oversized buffer: still parses correctly using the first 16 bytes
        let mut oversized = [0u8; 32];
        oversized[0] = 0;
        oversized[1] = 130; // TCP response
        oversized[8..10].copy_from_slice(&8080u16.to_be_bytes());
        oversized[10..12].copy_from_slice(&8080u16.to_be_bytes());
        let parsed = parse_nat_pmp_mapping_response(&oversized).unwrap();
        assert_eq!(parsed.protocol, NatPmpProtocol::Tcp);
        assert_eq!(parsed.internal_port, 8080);
    }

    #[test]
    fn test_nat_pmp_address_response_parsing() {
        let mut resp = [0u8; 12];
        resp[0] = 0;
        resp[1] = 128; // External address response
        resp[2..4].copy_from_slice(&0u16.to_be_bytes());
        resp[4..8].copy_from_slice(&9999u32.to_be_bytes());
        resp[8..12].copy_from_slice(&[203, 0, 113, 42]); // 203.0.113.42

        let parsed = parse_nat_pmp_address_response(&resp).unwrap();
        assert_eq!(parsed.result_code, NatPmpResultCode::Success);
        assert_eq!(parsed.epoch_seconds, 9999);
        assert_eq!(parsed.external_ip, Ipv4Addr::new(203, 0, 113, 42));
    }

    #[test]
    fn test_nat_pmp_address_response_all_result_codes_and_ips() {
        let ips = [
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(203, 0, 113, 42),
            Ipv4Addr::new(255, 255, 255, 255),
        ];

        for &ip in &ips {
            let mut resp = [0u8; 12];
            resp[0] = 0;
            resp[1] = 128; // External IP response
            resp[2..4].copy_from_slice(&0u16.to_be_bytes()); // Success
            resp[4..8].copy_from_slice(&5555u32.to_be_bytes());
            resp[8..12].copy_from_slice(&ip.octets());

            let parsed = parse_nat_pmp_address_response(&resp).expect("Failed to parse address response");
            assert_eq!(parsed.result_code, NatPmpResultCode::Success);
            assert_eq!(parsed.epoch_seconds, 5555);
            assert_eq!(parsed.external_ip, ip);
        }
    }

    #[test]
    fn test_nat_pmp_address_response_malformed() {
        assert!(parse_nat_pmp_address_response(&[]).is_err());
        assert!(parse_nat_pmp_address_response(&[0u8; 11]).is_err());

        // Version mismatch
        let mut bad_ver = [0u8; 12];
        bad_ver[0] = 1;
        bad_ver[1] = 128;
        assert!(parse_nat_pmp_address_response(&bad_ver).is_err());

        // Wrong OP
        let mut bad_op = [0u8; 12];
        bad_op[0] = 0;
        bad_op[1] = 129;
        assert!(parse_nat_pmp_address_response(&bad_op).is_err());
    }
}
