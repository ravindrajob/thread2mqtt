//! Thread2MQTT Z2M-Plus Diagnostics, SRP Correlation, Matter Setup Code Decoder,
//! RF Coexistence Analyzer, Mesh Health Advisor & Persistent Node Metadata Store.
//! 100% pure Rust `std` — zero external dependencies.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::matter_ws::parse_json;
use crate::{json_escape, json_str, BorderRouterInfo, ThreadNode, ThreadRole};

// ============================================================================
// 1. Whitelisted Read-Only `ot-ctl` Dev Console Commands (Zero Command Injection)
// ============================================================================

pub const WHITELISTED_OTCTL_COMMANDS: &[&str] = &[
    "state",
    "router table",
    "child table",
    "neighbor table",
    "counters mac",
    "counters ip",
    "srp server service",
    "ipaddr",
    "netdata show",
    "br omrprefix",
    "br onlinkprefix",
    "channel",
    "panid",
    "extpanid",
    "version",
];

pub fn is_whitelisted_otctl(cmd: &str) -> bool {
    let norm = cmd.trim();
    WHITELISTED_OTCTL_COMMANDS.contains(&norm)
}

// ============================================================================
// 2. MAC & IPv6 Radio Counters (`ot-ctl counters mac` / `counters ip`)
// ============================================================================

#[derive(Clone, Debug, Default)]
pub struct MacCounters {
    pub tx_total: u64,
    pub tx_unicast: u64,
    pub tx_broadcast: u64,
    pub tx_ack_requested: u64,
    pub tx_acked: u64,
    pub tx_retry: u64,
    pub tx_err_cca: u64,
    pub tx_err_busy_channel: u64,
    pub tx_err_abort: u64,
    pub tx_direct_max_retry_expiry: u64,
    pub tx_indirect_max_retry_expiry: u64,
    pub rx_total: u64,
    pub rx_unicast: u64,
    pub rx_data_poll: u64,
    pub rx_duplicated: u64,
    pub rx_err_fcs: u64,
    pub rx_err_sec: u64,
}

impl MacCounters {
    pub fn ack_rate_pct(&self) -> f64 {
        if self.tx_ack_requested == 0 {
            100.0
        } else {
            ((self.tx_acked as f64) * 100.0 / (self.tx_ack_requested as f64)).clamp(0.0, 100.0)
        }
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"tx_total\":{},\"tx_unicast\":{},\"tx_broadcast\":{},\"tx_ack_requested\":{},\"tx_acked\":{},\"ack_rate_pct\":{:.2},\"tx_retry\":{},\"tx_err_cca\":{},\"tx_err_busy_channel\":{},\"tx_err_abort\":{},\"tx_direct_max_retry_expiry\":{},\"tx_indirect_max_retry_expiry\":{},\"rx_total\":{},\"rx_unicast\":{},\"rx_data_poll\":{},\"rx_duplicated\":{},\"rx_err_fcs\":{},\"rx_err_sec\":{}}}",
            self.tx_total,
            self.tx_unicast,
            self.tx_broadcast,
            self.tx_ack_requested,
            self.tx_acked,
            self.ack_rate_pct(),
            self.tx_retry,
            self.tx_err_cca,
            self.tx_err_busy_channel,
            self.tx_err_abort,
            self.tx_direct_max_retry_expiry,
            self.tx_indirect_max_retry_expiry,
            self.rx_total,
            self.rx_unicast,
            self.rx_data_poll,
            self.rx_duplicated,
            self.rx_err_fcs,
            self.rx_err_sec
        )
    }
}

pub fn parse_otctl_mac_counters(raw: &str) -> MacCounters {
    let mut c = MacCounters::default();
    for line in raw.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let Ok(n) = v.trim().parse::<u64>() else {
            continue;
        };
        match k.trim() {
            "TxTotal" => c.tx_total = n,
            "TxUnicast" => c.tx_unicast = n,
            "TxBroadcast" => c.tx_broadcast = n,
            "TxAckRequested" => c.tx_ack_requested = n,
            "TxAcked" => c.tx_acked = n,
            "TxRetry" => c.tx_retry = n,
            "TxErrCca" => c.tx_err_cca = n,
            "TxErrBusyChannel" => c.tx_err_busy_channel = n,
            "TxErrAbort" => c.tx_err_abort = n,
            "TxDirectMaxRetryExpiry" => c.tx_direct_max_retry_expiry = n,
            "TxIndirectMaxRetryExpiry" => c.tx_indirect_max_retry_expiry = n,
            "RxTotal" => c.rx_total = n,
            "RxUnicast" => c.rx_unicast = n,
            "RxDataPoll" => c.rx_data_poll = n,
            "RxDuplicated" => c.rx_duplicated = n,
            "RxErrFcs" => c.rx_err_fcs = n,
            "RxErrSec" => c.rx_err_sec = n,
            _ => {}
        }
    }
    c
}

#[derive(Clone, Debug, Default)]
pub struct IpCounters {
    pub tx_success: u64,
    pub tx_failed: u64,
    pub rx_success: u64,
    pub rx_failed: u64,
}

impl IpCounters {
    pub fn delivery_rate_pct(&self) -> f64 {
        let total = self.tx_success + self.tx_failed;
        if total == 0 {
            100.0
        } else {
            ((self.tx_success as f64) * 100.0 / (total as f64)).clamp(0.0, 100.0)
        }
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"tx_success\":{},\"tx_failed\":{},\"rx_success\":{},\"rx_failed\":{},\"delivery_rate_pct\":{:.2}}}",
            self.tx_success,
            self.tx_failed,
            self.rx_success,
            self.rx_failed,
            self.delivery_rate_pct()
        )
    }
}

pub fn parse_otctl_ip_counters(raw: &str) -> IpCounters {
    let mut c = IpCounters::default();
    for line in raw.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let Ok(n) = v.trim().parse::<u64>() else {
            continue;
        };
        match k.trim() {
            "TxSuccess" => c.tx_success = n,
            "TxFailed" => c.tx_failed = n,
            "RxSuccess" => c.rx_success = n,
            "RxFailed" => c.rx_failed = n,
            _ => {}
        }
    }
    c
}

// ============================================================================
// 3. SRP Service Parser (`ot-ctl srp server service`) — Deterministic Thread↔Matter Link
// ============================================================================

#[derive(Clone, Debug, Default)]
pub struct SrpServiceRecord {
    pub instance_name: String,
    pub fabric_id: String,
    pub matter_node_id: Option<u64>,
    pub ext_address: String,
    pub ipv6_omr: String,
    pub port: u16,
    pub lease_remaining_s: u32,
    pub icd_sii_ms: Option<u32>,
    pub icd_sai_ms: Option<u32>,
    pub deleted: bool,
}

impl SrpServiceRecord {
    pub fn to_json(&self) -> String {
        let mn = self
            .matter_node_id
            .map(|n| n.to_string())
            .unwrap_or_else(|| "null".to_string());
        let sii = self
            .icd_sii_ms
            .map(|n| n.to_string())
            .unwrap_or_else(|| "null".to_string());
        let sai = self
            .icd_sai_ms
            .map(|n| n.to_string())
            .unwrap_or_else(|| "null".to_string());
        format!(
            "{{\"instance_name\":{},\"fabric_id\":{},\"matter_node_id\":{},\"ext_address\":{},\"ipv6_omr\":{},\"port\":{},\"lease_remaining_s\":{},\"icd_sii_ms\":{},\"icd_sai_ms\":{},\"deleted\":{}}}",
            json_str(&self.instance_name),
            json_str(&self.fabric_id),
            mn,
            json_str(&self.ext_address),
            json_str(&self.ipv6_omr),
            self.port,
            self.lease_remaining_s,
            sii,
            sai,
            self.deleted
        )
    }
}

fn decode_hex_ascii_u32(hex: &str) -> Option<u32> {
    let h = hex.trim();
    if h.is_empty() || h.len() % 2 != 0 {
        return None;
    }
    let mut s = String::new();
    for i in (0..h.len()).step_by(2) {
        let b = u8::from_str_radix(&h[i..i + 2], 16).ok()?;
        s.push(b as char);
    }
    s.trim().parse::<u32>().ok()
}

/// Parses `ot-ctl srp server service` output to bind Thread Extended MAC + IPv6 OMR
/// directly onto Matter Node ID (`<FabricHex>-<NodeIdHex>._matter._tcp...`).
pub fn parse_otctl_srp_services(raw: &str) -> Vec<SrpServiceRecord> {
    let mut records = Vec::new();
    let mut current: Option<SrpServiceRecord> = None;

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed == "Done" {
            continue;
        }
        if !line.starts_with(' ') && !line.starts_with('\t') {
            if let Some(rec) = current.take() {
                records.push(rec);
            }
            let mut rec = SrpServiceRecord {
                instance_name: trimmed.to_string(),
                ..Default::default()
            };
            // Parse Matter operational instance: <16hexFabric>-<16hexNodeId>._matter._tcp...
            if let Some(prefix) = trimmed.split("._matter.").next() {
                if let Some((fab, node_hex)) = prefix.split_once('-') {
                    rec.fabric_id = fab.to_ascii_uppercase();
                    if let Ok(nid) = u64::from_str_radix(node_hex, 16) {
                        rec.matter_node_id = Some(nid);
                    }
                }
            }
            current = Some(rec);
            continue;
        }
        if let Some(rec) = current.as_mut() {
            if let Some((k, v)) = trimmed.split_once(':') {
                let val = v.trim();
                match k.trim() {
                    "deleted" => rec.deleted = val == "true",
                    "port" => rec.port = val.parse::<u16>().unwrap_or(5540),
                    "remaining lease" => {
                        rec.lease_remaining_s = val.split('.').next().and_then(|s| s.parse().ok()).unwrap_or(0);
                    }
                    "host" => {
                        if let Some(mac) = val.split('.').next() {
                            if mac.len() == 16 && mac.chars().all(|c| c.is_ascii_hexdigit()) {
                                rec.ext_address = mac.to_ascii_lowercase();
                            }
                        }
                    }
                    "addresses" => {
                        let inner = val.trim_start_matches('[').trim_end_matches(']');
                        if let Some(first) = inner.split(',').next() {
                            rec.ipv6_omr = first.trim().to_string();
                        }
                    }
                    "TXT" => {
                        let inner = val.trim_start_matches('[').trim_end_matches(']');
                        for kv in inner.split(',') {
                            if let Some((tk, tv)) = kv.trim().split_once('=') {
                                match tk.trim() {
                                    "SII" => rec.icd_sii_ms = decode_hex_ascii_u32(tv),
                                    "SAI" => rec.icd_sai_ms = decode_hex_ascii_u32(tv),
                                    _ => {}
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    if let Some(rec) = current {
        records.push(rec);
    }
    records
}

// ============================================================================
// 4. IEEE 802.15.4 Energy Scan (`ot-ctl scan energy`)
// ============================================================================

#[derive(Clone, Debug)]
pub struct EnergyScanChannel {
    pub channel: u8,
    pub max_rssi_dbm: i32,
}

impl EnergyScanChannel {
    pub fn to_json(&self) -> String {
        format!("{{\"channel\":{},\"max_rssi_dbm\":{}}}", self.channel, self.max_rssi_dbm)
    }
}

pub fn parse_otctl_energy_scan(raw: &str) -> Vec<EnergyScanChannel> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let l = line.trim();
        if !l.starts_with('|') || l.contains("Ch") {
            continue;
        }
        let cols: Vec<&str> = l.split('|').map(|c| c.trim()).filter(|c| !c.is_empty()).collect();
        if cols.len() >= 2 {
            if let (Ok(ch), Ok(rssi)) = (cols[0].parse::<u8>(), cols[1].parse::<i32>()) {
                if (11..=26).contains(&ch) {
                    out.push(EnergyScanChannel {
                        channel: ch,
                        max_rssi_dbm: rssi,
                    });
                }
            }
        }
    }
    out
}

// ============================================================================
// 5. Universal Matter Setup Code Decoder (Base38 `MT:...` QR & 11/21-Digit Manual)
// ============================================================================

#[derive(Clone, Debug)]
pub struct DecodedMatterCode {
    pub format: String,
    pub version: u8,
    pub vendor_id: u16,
    pub product_id: u16,
    pub commissioning_flow: u8,
    pub discovery_caps: String,
    pub discriminator: u16,
    pub passcode: u32,
    pub manual_hint: String,
}

impl DecodedMatterCode {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"format\":{},\"version\":{},\"vendor_id\":{},\"vendor_id_hex\":{},\"product_id\":{},\"product_id_hex\":{},\"commissioning_flow\":{},\"discovery_caps\":{},\"discriminator\":{},\"passcode\":{},\"manual_hint\":{}}}",
            json_str(&self.format),
            self.version,
            self.vendor_id,
            json_str(&format!("0x{:04X}", self.vendor_id)),
            self.product_id,
            json_str(&format!("0x{:04X}", self.product_id)),
            self.commissioning_flow,
            json_str(&self.discovery_caps),
            self.discriminator,
            self.passcode,
            json_str(&self.manual_hint)
        )
    }
}

fn base38_decode(s: &str) -> Result<Vec<u8>, String> {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-.";
    let chars: Vec<u8> = s.trim().to_ascii_uppercase().bytes().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let rem = chars.len() - i;
        let (chunk_len, out_bytes) = if rem >= 5 {
            (5, 3)
        } else if rem == 4 {
            (4, 2)
        } else if rem == 2 {
            (2, 1)
        } else {
            return Err("Invalid Base38 chunk length".to_string());
        };
        let mut val: u32 = 0;
        let mut mult: u32 = 1;
        for j in 0..chunk_len {
            let idx = ALPHABET
                .iter()
                .position(|&c| c == chars[i + j])
                .ok_or_else(|| format!("Invalid Base38 character '{}'", chars[i + j] as char))? as u32;
            val = val.saturating_add(idx.saturating_mul(mult));
            mult = mult.saturating_mul(38);
        }
        for b in 0..out_bytes {
            out.push(((val >> (8 * b)) & 0xff) as u8);
        }
        i += chunk_len;
    }
    Ok(out)
}

fn extract_bits_le(bytes: &[u8], start_bit: usize, bit_len: usize) -> u32 {
    let mut val: u32 = 0;
    for i in 0..bit_len {
        let bit_pos = start_bit + i;
        let byte_idx = bit_pos / 8;
        let bit_in_byte = bit_pos % 8;
        if byte_idx < bytes.len() && ((bytes[byte_idx] >> bit_in_byte) & 1) != 0 {
            val |= 1u32 << i;
        }
    }
    val
}

/// Matter Spec §5.1.4.1 Verhoeff check-digit validation for 11-digit & 21-digit manual codes.
fn verhoeff_valid(digits: &str) -> bool {
    const D: [[u8; 10]; 10] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
        [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
        [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
    ];
    const P: [[u8; 10]; 8] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
        [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
        [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
    ];
    let mut c: usize = 0;
    for (idx, b) in digits.bytes().rev().enumerate() {
        if !b.is_ascii_digit() {
            return false;
        }
        let digit = (b - b'0') as usize;
        c = D[c][P[idx % 8][digit] as usize] as usize;
    }
    c == 0
}

/// Decodes Matter QR (`MT:...`) and 11-digit / 21-digit manual pairing codes per Matter Spec §5.1.
pub fn decode_matter_setup_code(raw: &str) -> Result<DecodedMatterCode, String> {
    let s = raw.trim();
    if s.to_ascii_uppercase().starts_with("MT:") {
        let payload = &s[3..];
        let bytes = base38_decode(payload)?;
        if bytes.len() < 11 {
            return Err("QR payload too short (expected >= 88 bits)".to_string());
        }
        let version = extract_bits_le(&bytes, 0, 3) as u8;
        let vendor_id = extract_bits_le(&bytes, 3, 16) as u16;
        let product_id = extract_bits_le(&bytes, 19, 16) as u16;
        let commissioning_flow = extract_bits_le(&bytes, 35, 2) as u8;
        let disc_bits = extract_bits_le(&bytes, 37, 8);
        let discriminator = extract_bits_le(&bytes, 45, 12) as u16;
        let passcode = extract_bits_le(&bytes, 57, 27);

        let mut caps = Vec::new();
        if (disc_bits & 1) != 0 {
            caps.push("SoftAP");
        }
        if (disc_bits & 2) != 0 {
            caps.push("BLE");
        }
        if (disc_bits & 4) != 0 {
            caps.push("On-Network IP/Thread");
        }
        let discovery_caps = if caps.is_empty() {
            "On-Network".to_string()
        } else {
            caps.join(" + ")
        };

        return Ok(DecodedMatterCode {
            format: "Matter QR (Base38 MT:)".to_string(),
            version,
            vendor_id,
            product_id,
            commissioning_flow,
            discovery_caps,
            discriminator,
            passcode,
            manual_hint: format!(
                "Short Discriminator={} · Passcode={}",
                discriminator >> 8,
                passcode
            ),
        });
    }

    // Manual 11-digit or 21-digit pairing code (ignore dashes/spaces)
    let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() != 11 && digits.len() != 21 {
        return Err("Expected 'MT:...' QR payload or 11/21-digit Matter manual pairing code".to_string());
    }
    if !verhoeff_valid(&digits) {
        return Err("Invalid Verhoeff check digit in Matter manual pairing code".to_string());
    }
    let chunk1: u32 = digits[0..1].parse().map_err(|_| "Invalid digit 0")?;
    let chunk2: u32 = digits[1..6].parse().map_err(|_| "Invalid digits 1..6")?;
    let chunk3: u32 = digits[6..10].parse().map_err(|_| "Invalid digits 6..10")?;

    let short_disc = ((chunk1 & 0x3) << 2) | ((chunk2 >> 14) & 0x3);
    let passcode = (chunk2 & 0x3FFF) | ((chunk3 & 0x1FFF) << 14);
    let has_vid_pid = (chunk1 & 0x4) != 0;
    let (vendor_id, product_id) = if has_vid_pid && digits.len() == 21 {
        let vid: u16 = digits[10..15].parse().unwrap_or(0);
        let pid: u16 = digits[15..20].parse().unwrap_or(0);
        (vid, pid)
    } else {
        (0, 0)
    };

    Ok(DecodedMatterCode {
        format: format!("Matter Manual Code ({} digits)", digits.len()),
        version: 0,
        vendor_id,
        product_id,
        commissioning_flow: if has_vid_pid { 2 } else { 0 },
        discovery_caps: "BLE / On-Network".to_string(),
        discriminator: (short_disc as u16) << 8,
        passcode,
        manual_hint: format!(
            "{}-{}-{}",
            &digits[0..4],
            &digits[4..7],
            &digits[7..digits.len().min(11)]
        ),
    })
}

// ============================================================================
// 6. Smart Mesh Health Advisor (Node Score 0..100 + Actionable Diagnostics)
// ============================================================================

#[derive(Clone, Debug)]
pub struct HealthIssue {
    pub severity: String, // "ok" | "warn" | "crit"
    pub category: String, // "TOPOLOGY" | "RADIO" | "BATTERY" | "COEXISTENCE" | "MATTER" | "SRP"
    pub title: String,
    pub detail: String,
    pub recommendation: String,
}

impl HealthIssue {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"severity\":{},\"category\":{},\"title\":{},\"detail\":{},\"recommendation\":{}}}",
            json_str(&self.severity),
            json_str(&self.category),
            json_str(&self.title),
            json_str(&self.detail),
            json_str(&self.recommendation)
        )
    }
}

pub fn compute_node_health_score(n: &ThreadNode) -> u8 {
    let mut score: i32 = 100;
    if n.role != ThreadRole::Leader {
        if n.avg_rssi_dbm <= -90 {
            score -= 40;
        } else if n.avg_rssi_dbm <= -84 {
            score -= 22;
        } else if n.avg_rssi_dbm <= -76 {
            score -= 8;
        }
        if n.lq_in <= 1 {
            score -= 25;
        } else if n.lq_in == 2 {
            score -= 10;
        }
    }
    if let Some(pct) = n.battery_pct {
        if pct <= 10 {
            score -= 35;
        } else if pct <= 25 {
            score -= 15;
        }
    }
    if n.matter_node_id.is_some() && !n.matter_available {
        score -= 40;
    }
    if n.age_sec > 200 {
        score -= 15;
    }
    score.clamp(0, 100) as u8
}

/// Evaluates the Thread + Matter mesh and produces concrete CTO/SRE diagnostics.
pub fn analyze_mesh_health(
    br: &BorderRouterInfo,
    nodes: &[ThreadNode],
    mac: &MacCounters,
    ip: &IpCounters,
    zigbee_channel: Option<u8>,
) -> (u8, Vec<HealthIssue>) {
    let mut issues = Vec::new();
    let mut global_score: i32 = 100;

    // 1. Router redundancy check
    if br.router_count <= 1 && nodes.len() > 1 {
        global_score -= 12;
        issues.push(HealthIssue {
            severity: "warn".to_string(),
            category: "TOPOLOGY".to_string(),
            title: "Single Thread Router (No Mesh Redundancy)".to_string(),
            detail: format!("Only {} active router (Border Router {}) serving {} end-devices.", br.router_count, br.rloc16, nodes.len().saturating_sub(1)),
            recommendation: "Add at least 1 mains-powered Thread 1.3/1.4 router (smart plug or bulb) to eliminate single-hop dependency and improve SED battery life.".to_string(),
        });
    }

    // 2. Weak RSSI / LQI per node
    for n in nodes {
        if n.role != ThreadRole::Leader && n.avg_rssi_dbm <= -85 {
            global_score -= 14;
            issues.push(HealthIssue {
                severity: if n.avg_rssi_dbm <= -90 { "crit" } else { "warn" }.to_string(),
                category: "RADIO".to_string(),
                title: format!("Weak RF Signal on {} ({})", n.friendly_name, n.rloc16),
                detail: format!("Average RSSI is {} dBm (LQI {}/3, Last {} dBm).", n.avg_rssi_dbm, n.lq_in, n.last_rssi_dbm),
                recommendation: "Place a mains-powered Thread router halfway between the Border Router and this device to avoid indirect TX expiries.".to_string(),
            });
        }
        if let Some(pct) = n.battery_pct {
            if pct <= 20 {
                global_score -= 15;
                issues.push(HealthIssue {
                    severity: if pct <= 10 { "crit" } else { "warn" }.to_string(),
                    category: "BATTERY".to_string(),
                    title: format!("Low Battery on {} ({}%)", n.friendly_name, pct),
                    detail: format!("Battery reported at {}% ({} mV).", pct, n.battery_mv.unwrap_or(0)),
                    recommendation: format!("Replace {} battery soon to prevent Thread child timeout.", n.battery_type.as_deref().unwrap_or("device")),
                });
            }
        }
        if n.matter_node_id.is_some() && !n.matter_available {
            global_score -= 20;
            issues.push(HealthIssue {
                severity: "crit".to_string(),
                category: "MATTER".to_string(),
                title: format!("Matter Node #{} Unreachable ({})", n.matter_node_id.unwrap_or(0), n.friendly_name),
                detail: "Present in Thread L2/L3 table or Matter fabric, but CASE session is currently offline.".to_string(),
                recommendation: "Use Dev Console -> Matter Ping or check SRP lease expiry and device battery.".to_string(),
            });
        }
    }

    // 3. Thread vs Zigbee 2.4 GHz coexistence
    if let Some(zch) = zigbee_channel {
        let diff = (br.channel as i32 - zch as i32).abs();
        if diff <= 2 {
            global_score -= 18;
            issues.push(HealthIssue {
                severity: "crit".to_string(),
                category: "COEXISTENCE".to_string(),
                title: format!("RF Overlap: Thread CH {} vs Zigbee CH {}", br.channel, zch),
                detail: format!("Channel spacing is only {} channel(s) ({} MHz).", diff, diff * 5),
                recommendation: "Separate Thread and Zigbee by at least 4 channels (recommended: Zigbee CH 11 + Thread CH 25, outside Wi-Fi Ch 1/6/11 lobes).".to_string(),
            });
        } else {
            issues.push(HealthIssue {
                severity: "ok".to_string(),
                category: "COEXISTENCE".to_string(),
                title: format!("Clean Orthogonal 2.4 GHz Plan (Thread CH {} · Zigbee CH {})", br.channel, zch),
                detail: format!("{} MHz RF separation between Thread and Zigbee coordinators.", diff * 5),
                recommendation: "Optimal side-band isolation maintained.".to_string(),
            });
        }
    }

    // 4. MAC / IPv6 reliability check
    if mac.tx_indirect_max_retry_expiry > 50 {
        global_score -= 6;
        issues.push(HealthIssue {
            severity: "warn".to_string(),
            category: "RADIO".to_string(),
            title: format!("MAC Indirect TX Retry Expiries ({})", mac.tx_indirect_max_retry_expiry),
            detail: format!("MAC ACK rate {:.1}% · CCA busy errors: {} · IPv6 delivery {:.2}%.", mac.ack_rate_pct(), mac.tx_err_cca, ip.delivery_rate_pct()),
            recommendation: "Sleepy End Devices (SEDs) missed indirect polls (often due to weak RSSI <= -85 dBm or long ICD SII interval).".to_string(),
        });
    }

    if issues.iter().all(|i| i.severity == "ok") {
        issues.push(HealthIssue {
            severity: "ok".to_string(),
            category: "TOPOLOGY".to_string(),
            title: "Thread Mesh Nominal".to_string(),
            detail: format!("Leader {} active on CH {} with {} healthy nodes and {:.2}% IPv6 delivery.", br.rloc16, br.channel, nodes.len(), ip.delivery_rate_pct()),
            recommendation: "No action required.".to_string(),
        });
    }

    (global_score.clamp(0, 100) as u8, issues)
}

// ============================================================================
// 7. Persistent JSON Node Metadata Store (Friendly Names, Groups, Descriptions)
// ============================================================================

#[derive(Clone, Debug, Default)]
pub struct NodeMeta {
    pub friendly_name: Option<String>,
    pub group: Option<String>,
    pub description: Option<String>,
    pub icon: Option<String>,
}

pub fn load_node_meta_store(data_dir: &str) -> BTreeMap<String, NodeMeta> {
    let mut map = BTreeMap::new();
    let path = Path::new(data_dir).join("state.json");
    let Ok(raw) = fs::read_to_string(&path) else {
        return map;
    };
    let Some(val) = parse_json(&raw) else {
        return map;
    };
    if let Some(obj) = val.get("nodes").and_then(|v| v.as_obj()) {
        for (ext, entry) in obj {
            let meta = NodeMeta {
                friendly_name: entry.get("friendly_name").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(|s| s.to_string()),
                group: entry.get("group").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(|s| s.to_string()),
                description: entry.get("description").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(|s| s.to_string()),
                icon: entry.get("icon").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(|s| s.to_string()),
            };
            map.insert(ext.to_ascii_lowercase(), meta);
        }
    }
    map
}

pub fn save_node_meta_store(data_dir: &str, store: &BTreeMap<String, NodeMeta>) -> Result<(), String> {
    let dir = Path::new(data_dir);
    fs::create_dir_all(dir).map_err(|e| format!("create_dir_all {}: {}", data_dir, e))?;
    let mut entries = Vec::new();
    for (ext, meta) in store {
        let fn_j = meta.friendly_name.as_deref().map(json_str).unwrap_or_else(|| "null".to_string());
        let gp_j = meta.group.as_deref().map(json_str).unwrap_or_else(|| "null".to_string());
        let ds_j = meta.description.as_deref().map(json_str).unwrap_or_else(|| "null".to_string());
        let ic_j = meta.icon.as_deref().map(json_str).unwrap_or_else(|| "null".to_string());
        entries.push(format!(
            "\"{}\":{{\"friendly_name\":{},\"group\":{},\"description\":{},\"icon\":{}}}",
            json_escape(ext),
            fn_j,
            gp_j,
            ds_j,
            ic_j
        ));
    }
    let body = format!("{{\"version\":1,\"nodes\":{{{}}}}}", entries.join(","));
    let tmp = dir.join("state.json.tmp");
    let final_p = dir.join("state.json");
    fs::write(&tmp, body).map_err(|e| format!("write tmp state: {}", e))?;
    fs::rename(&tmp, &final_p).map_err(|e| format!("rename state.json: {}", e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mac_ip_and_srp_tables() {
        let mac_raw = "TxTotal: 10000\nTxAckRequested: 2000\nTxAcked: 1940\nTxErrCca: 2\nTxIndirectMaxRetryExpiry: 15\nRxTotal: 8500\nRxDataPoll: 6000\nDone\n";
        let mac = parse_otctl_mac_counters(mac_raw);
        assert_eq!(mac.tx_total, 10000);
        assert_eq!(mac.tx_err_cca, 2);
        assert!(mac.ack_rate_pct() > 95.0);

        let ip_raw = "TxSuccess: 5000\nTxFailed: 10\nRxSuccess: 1200\nRxFailed: 1\nDone\n";
        let ip = parse_otctl_ip_counters(ip_raw);
        assert_eq!(ip.tx_success, 5000);
        assert!(ip.delivery_rate_pct() > 99.5);

        let srp_raw = "\
AAAABBBBCCCCDDDD-000000000000000C._matter._tcp.default.service.arpa.
    deleted: false
    port: 5540
    remaining lease: 3600.000
    TXT: [SII=3137303030, SAI=33303030]
    host: 020000000000000C.default.service.arpa.
    addresses: [fd00:db8:1::c]
Done";
        let recs = parse_otctl_srp_services(srp_raw);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].matter_node_id, Some(12));
        assert_eq!(recs[0].ext_address, "020000000000000c");
        assert_eq!(recs[0].ipv6_omr, "fd00:db8:1::c");
        assert_eq!(recs[0].icd_sii_ms, Some(17000));
        assert_eq!(recs[0].icd_sai_ms, Some(3000));
    }

    #[test]
    fn test_decode_matter_qr_and_manual_code() {
        // Standard Matter SDK reference test vector MT:Y.K9042C00KA0648G00
        let qr = decode_matter_setup_code("MT:Y.K9042C00KA0648G00").expect("QR decode ok");
        assert_eq!(qr.version, 0);
        assert_eq!(qr.vendor_id, 65521);
        assert_eq!(qr.product_id, 32768);
        assert_eq!(qr.discriminator, 3840);
        assert_eq!(qr.passcode, 20202021);

        // Standard Matter SDK manual test vector 3497-011-2332 (valid Verhoeff check digit)
        let manual = decode_matter_setup_code("3497-011-2332").expect("manual decode ok");
        assert_eq!(manual.passcode, 20202021);
        assert_eq!(manual.discriminator >> 8, 15);
        // Mutated check digit must be rejected by Verhoeff checksum
        assert!(decode_matter_setup_code("3497-011-2339").is_err());
    }

    #[test]
    fn test_otctl_command_whitelist_blocks_injection() {
        assert!(is_whitelisted_otctl("counters mac"));
        assert!(is_whitelisted_otctl("srp server service"));
        assert!(!is_whitelisted_otctl("factoryreset"));
        assert!(!is_whitelisted_otctl("dataset active -x"));
        assert!(!is_whitelisted_otctl("state; rm -rf /"));
    }
}
