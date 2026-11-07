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
                info!("STUN resolved external mapped address: {}", resolved);
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
    let first_line = lines.next()?.trim();

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
    let first_line = lines.next()?.trim();

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
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_nat_pmp_port_deletion_generation() {
        let del = generate_nat_pmp_port_deletion(NatPmpProtocol::Udp, 9190);
        assert_eq!(del[0], 0);
        assert_eq!(del[1], 1);
        assert_eq!(u16::from_be_bytes([del[4], del[5]]), 9190);
        assert_eq!(u16::from_be_bytes([del[6], del[7]]), 0);
        assert_eq!(u32::from_be_bytes([del[8], del[9], del[10], del[11]]), 0);
    }

    #[test]
    fn test_nat_pmp_external_address_request() {
        let req = generate_nat_pmp_external_address_request();
        assert_eq!(req, [0x00, 0x00]);
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
}
