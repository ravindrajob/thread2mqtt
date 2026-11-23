//! Thread2MQTT — Pure-Rust Thread (OTBR) & Matter-over-Thread to MQTT bridge
//! with Home Assistant Auto-Discovery, interactive Mesh Debugger, and Prometheus metrics.
//!
//! Zero external crate dependencies: relies strictly on the Rust standard library.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub mod config;
pub mod diagnostics;
pub mod matter_ws;

use diagnostics::{
    analyze_mesh_health, compute_node_health_score, EnergyScanChannel, HealthIssue, IpCounters,
    MacCounters, NodeMeta, SrpServiceRecord,
};
use matter_ws::{LiveMatterNode, MatterExpose, MatterFabricInfo};

// ============================================================================
// 1. Minimal RFC 8259 JSON Helpers (Zero external crates)
// ============================================================================

pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

pub fn json_str(s: &str) -> String {
    format!("\"{}\"", json_escape(s))
}

/// Extracts a string value for `"key": "value"` from flat or lightly nested JSON.
pub fn json_get_str(raw: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\"", key);
    let idx = raw.find(&needle)?;
    let rest = raw[idx + needle.len()..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let mut out = String::new();
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(esc) = chars.next() {
                match esc {
                    '"' => out.push('"'),
                    '\\' => out.push('\\'),
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    other => out.push(other),
                }
            }
        } else if c == '"' {
            return Some(out);
        } else {
            out.push(c);
        }
    }
    None
}

/// Extracts a numeric (i64) value for `"key": 12345` from JSON.
pub fn json_get_i64(raw: &str, key: &str) -> Option<i64> {
    let needle = format!("\"{}\"", key);
    let idx = raw.find(&needle)?;
    let rest = raw[idx + needle.len()..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let num_str: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '-')
        .collect();
    if num_str.is_empty() {
        return None;
    }
    num_str.parse::<i64>().ok()
}

/// Masks a sensitive hex key (Network Key / PSKc) keeping only last 4 hex chars.
pub fn mask_secret_hex(raw: &str) -> String {
    let clean = raw.trim();
    if clean.is_empty() {
        return "not-set".to_string();
    }
    if clean.len() <= 4 {
        return "****".to_string();
    }
    format!("****...{}", &clean[clean.len() - 4..])
}

/// Zero-Trust invariant: guarantees sensitive Thread cryptographic keys never leak into MQTT.
pub fn sanitize_mqtt_payload(payload: &str) -> String {
    let mut out = payload.to_string();
    for secret_key in ["\"networkKey\"", "\"network_key\"", "\"pskc\"", "\"PSKc\""] {
        let mut cursor = 0;
        while let Some(rel_pos) = out[cursor..].find(secret_key) {
            let pos = cursor + rel_pos;
            let after_key = pos + secret_key.len();
            if let Some(colon) = out[after_key..].find(':') {
                let val_start = after_key + colon + 1;
                if let Some(q1) = out[val_start..].find('"') {
                    let s1 = val_start + q1 + 1;
                    if let Some(q2) = out[s1..].find('"') {
                        out.replace_range(s1..s1 + q2, "REDACTED");
                        cursor = s1 + "REDACTED".len() + 1;
                        continue;
                    }
                }
            }
            cursor = after_key;
        }
    }
    out
}

pub fn now_epoch_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ============================================================================
// 2. Domain Model (Thread L2/L3 + Correlated Matter L7)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreadRole {
    Leader,
    Router,
    Child,
    Sed,
    Detached,
    Disabled,
}

impl ThreadRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            ThreadRole::Leader => "leader",
            ThreadRole::Router => "router",
            ThreadRole::Child => "child",
            ThreadRole::Sed => "sed",
            ThreadRole::Detached => "detached",
            ThreadRole::Disabled => "disabled",
        }
    }

    pub fn from_ot_str(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "leader" => ThreadRole::Leader,
            "router" | "r" => ThreadRole::Router,
            "child" | "c" => ThreadRole::Child,
            "sed" => ThreadRole::Sed,
            "detached" => ThreadRole::Detached,
            _ => ThreadRole::Disabled,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BorderRouterInfo {
    pub state: String,
    pub network_name: String,
    pub ext_pan_id: String,
    pub pan_id: String,
    pub channel: u8,
    pub rloc16: String,
    pub ext_address: String,
    pub rloc_address: String,
    pub mesh_local_prefix: String,
    pub partition_id: u64,
    pub leader_weight: u32,
    pub router_count: u32,
    pub srp_state: String,
    pub br_state: String,
    pub network_key_masked: String,
    pub pskc_masked: String,
}

impl Default for BorderRouterInfo {
    fn default() -> Self {
        Self {
            state: "disabled".to_string(),
            network_name: "Unknown-Thread".to_string(),
            ext_pan_id: "0000000000000000".to_string(),
            pan_id: "0x0000".to_string(),
            channel: 0,
            rloc16: "0x0000".to_string(),
            ext_address: "0000000000000000".to_string(),
            rloc_address: "::".to_string(),
            mesh_local_prefix: "fd00:db8::/64".to_string(),
            partition_id: 0,
            leader_weight: 0,
            router_count: 0,
            srp_state: "unknown".to_string(),
            br_state: "unknown".to_string(),
            network_key_masked: "not-set".to_string(),
            pskc_masked: "not-set".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MatterDeviceSummary {
    pub node_id: u32,
    pub ext_address: String,
    pub vendor: String,
    pub product: String,
    pub state_summary: String,
    pub clusters: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ThreadNode {
    pub rloc16: String,
    pub ext_address: String,
    pub friendly_name: String,
    pub role: ThreadRole,
    pub parent_rloc16: Option<String>,
    pub avg_rssi_dbm: i32,
    pub last_rssi_dbm: i32,
    pub lq_in: u8,
    pub lq_out: u8,
    pub path_cost: u8,
    pub age_sec: u32,
    pub child_timeout_sec: u32,
    pub thread_version: u8,
    pub is_sleepy: bool,
    pub ipv6_omr: Option<String>,
    pub srp_service: Option<String>,
    pub srp_lease_remaining_s: Option<u32>,
    pub icd_sii_ms: Option<u32>,
    pub matter_node_id: Option<u32>,
    pub matter_vendor: Option<String>,
    pub matter_product: Option<String>,
    pub matter_serial: Option<String>,
    pub matter_sw_version: Option<String>,
    pub matter_hw_version: Option<String>,
    pub matter_available: bool,
    pub matter_state: Option<String>,
    pub matter_clusters: Vec<String>,
    pub battery_pct: Option<u8>,
    pub battery_mv: Option<u32>,
    pub battery_type: Option<String>,
    pub exposes: Vec<MatterExpose>,
    pub fabrics: Vec<MatterFabricInfo>,
    pub group: Option<String>,
    pub description: Option<String>,
    pub icon: Option<String>,
    pub health_score: u8,
    pub rssi_history: Vec<i32>,
}

impl Default for ThreadNode {
    fn default() -> Self {
        Self {
            rloc16: "0x0000".to_string(),
            ext_address: String::new(),
            friendly_name: String::new(),
            role: ThreadRole::Child,
            parent_rloc16: None,
            avg_rssi_dbm: 0,
            last_rssi_dbm: 0,
            lq_in: 0,
            lq_out: 0,
            path_cost: 0,
            age_sec: 0,
            child_timeout_sec: 0,
            thread_version: 4,
            is_sleepy: false,
            ipv6_omr: None,
            srp_service: None,
            srp_lease_remaining_s: None,
            icd_sii_ms: None,
            matter_node_id: None,
            matter_vendor: None,
            matter_product: None,
            matter_serial: None,
            matter_sw_version: None,
            matter_hw_version: None,
            matter_available: true,
            matter_state: None,
            matter_clusters: Vec::new(),
            battery_pct: None,
            battery_mv: None,
            battery_type: None,
            exposes: Vec::new(),
            fabrics: Vec::new(),
            group: None,
            description: None,
            icon: None,
            health_score: 100,
            rssi_history: Vec::new(),
        }
    }
}

impl ThreadNode {
    pub fn signal_quality(&self) -> &'static str {
        if self.role == ThreadRole::Leader {
            return "leader";
        }
        if self.avg_rssi_dbm >= -65 && self.lq_in >= 3 {
            "excellent"
        } else if self.avg_rssi_dbm >= -78 && self.lq_in >= 2 {
            "good"
        } else if self.avg_rssi_dbm >= -88 {
            "fair"
        } else {
            "weak"
        }
    }

    pub fn to_json(&self) -> String {
        let opt_s = |o: &Option<String>| o.as_deref().map(json_str).unwrap_or_else(|| "null".to_string());
        let opt_u = |o: Option<u32>| o.map(|v| v.to_string()).unwrap_or_else(|| "null".to_string());
        let clusters_json = self.matter_clusters.iter().map(|c| json_str(c)).collect::<Vec<_>>().join(",");
        let exposes_json = self
            .exposes
            .iter()
            .map(|e| {
                format!(
                    "{{\"name\":{},\"property\":{},\"value\":{},\"unit\":{},\"cluster\":{},\"access\":{}}}",
                    json_str(&e.name),
                    json_str(&e.property),
                    json_str(&e.value),
                    json_str(&e.unit),
                    json_str(&e.cluster),
                    json_str(&e.access)
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let fabrics_json = self
            .fabrics
            .iter()
            .map(|f| {
                format!(
                    "{{\"fabric_index\":{},\"vendor_id\":{},\"label\":{},\"node_id\":{}}}",
                    f.fabric_index,
                    f.vendor_id,
                    json_str(&f.label),
                    f.node_id
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let bat_pct = self.battery_pct.map(|v| v.to_string()).unwrap_or_else(|| "null".to_string());
        let rssi_hist_j = self
            .rssi_history
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"rloc16\":{},\"ext_address\":{},\"friendly_name\":{},\"role\":{},\"parent_rloc16\":{},\"avg_rssi_dbm\":{},\"last_rssi_dbm\":{},\"lq_in\":{},\"lq_out\":{},\"path_cost\":{},\"age_sec\":{},\"child_timeout_sec\":{},\"thread_version\":{},\"is_sleepy\":{},\"signal_quality\":{},\"health_score\":{},\"ipv6_omr\":{},\"srp_service\":{},\"srp_lease_remaining_s\":{},\"icd_sii_ms\":{},\"matter_node_id\":{},\"matter_vendor\":{},\"matter_product\":{},\"matter_serial\":{},\"matter_sw_version\":{},\"matter_hw_version\":{},\"matter_available\":{},\"matter_state\":{},\"matter_clusters\":[{}],\"battery_pct\":{},\"battery_mv\":{},\"battery_type\":{},\"exposes\":[{}],\"fabrics\":[{}],\"group\":{},\"description\":{},\"icon\":{},\"rssi_history\":[{}]}}",
            json_str(&self.rloc16),
            json_str(&self.ext_address),
            json_str(&self.friendly_name),
            json_str(self.role.as_str()),
            opt_s(&self.parent_rloc16),
            self.avg_rssi_dbm,
            self.last_rssi_dbm,
            self.lq_in,
            self.lq_out,
            self.path_cost,
            self.age_sec,
            self.child_timeout_sec,
            self.thread_version,
            self.is_sleepy,
            json_str(self.signal_quality()),
            self.health_score,
            opt_s(&self.ipv6_omr),
            opt_s(&self.srp_service),
            opt_u(self.srp_lease_remaining_s),
            opt_u(self.icd_sii_ms),
            opt_u(self.matter_node_id),
            opt_s(&self.matter_vendor),
            opt_s(&self.matter_product),
            opt_s(&self.matter_serial),
            opt_s(&self.matter_sw_version),
            opt_s(&self.matter_hw_version),
            self.matter_available,
            opt_s(&self.matter_state),
            clusters_json,
            bat_pct,
            opt_u(self.battery_mv),
            opt_s(&self.battery_type),
            exposes_json,
            fabrics_json,
            opt_s(&self.group),
            opt_s(&self.description),
            opt_s(&self.icon),
            rssi_hist_j
        )
    }
}

#[derive(Debug, Clone)]
pub struct MeshLink {
    pub source_rloc16: String,
    pub target_rloc16: String,
    pub rssi_dbm: i32,
    pub lqi: u8,
    pub quality: String,
}

impl MeshLink {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"source\":{},\"target\":{},\"rssi_dbm\":{},\"lqi\":{},\"quality\":{}}}",
            json_str(&self.source_rloc16),
            json_str(&self.target_rloc16),
            self.rssi_dbm,
            self.lqi,
            json_str(&self.quality)
        )
    }
}

#[derive(Debug, Clone)]
pub struct DebugEvent {
    pub seq: u64,
    pub ts_epoch_s: u64,
    pub level: String,
    pub source: String,
    pub summary: String,
    pub payload_json: String,
}

impl DebugEvent {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"seq\":{},\"ts\":{},\"level\":{},\"source\":{},\"summary\":{},\"payload\":{}}}",
            self.seq,
            self.ts_epoch_s,
            json_str(&self.level),
            json_str(&self.source),
            json_str(&self.summary),
            json_str(&self.payload_json)
        )
    }
}

#[derive(Debug, Clone)]
pub struct MeshSnapshot {
    pub updated_at_s: u64,
    pub demo_mode: bool,
    pub otbr_source: String,
    pub mqtt_connected: bool,
    pub matter_connected: bool,
    pub matter_bluetooth_enabled: bool,
    pub matter_sdk_version: String,
    pub matter_fabric_id: String,
    pub zigbee_channel: Option<u8>,
    pub br: BorderRouterInfo,
    pub br_ipaddrs: Vec<String>,
    pub br_omr_prefix: String,
    pub mac_counters: MacCounters,
    pub ip_counters: IpCounters,
    pub srp_services: Vec<SrpServiceRecord>,
    pub energy_scan: Vec<EnergyScanChannel>,
    pub mesh_health_score: u8,
    pub health_issues: Vec<HealthIssue>,
    pub nodes: Vec<ThreadNode>,
    pub links: Vec<MeshLink>,
    pub friendly_names: BTreeMap<String, String>,
    pub node_meta: BTreeMap<String, NodeMeta>,
    pub rssi_history_map: BTreeMap<String, Vec<i32>>,
    pub events: Vec<DebugEvent>,
}

impl MeshSnapshot {
    pub fn push_event(&mut self, level: &str, source: &str, summary: &str, payload: &str) {
        let next_seq = self.events.last().map(|e| e.seq + 1).unwrap_or(1);
        self.events.push(DebugEvent {
            seq: next_seq,
            ts_epoch_s: now_epoch_s(),
            level: level.to_string(),
            source: source.to_string(),
            summary: summary.to_string(),
            payload_json: sanitize_mqtt_payload(payload),
        });
        if self.events.len() > 250 {
            let drain_n = self.events.len() - 250;
            self.events.drain(0..drain_n);
        }
    }

    pub fn to_json(&self) -> String {
        let nodes_j = self.nodes.iter().map(|n| n.to_json()).collect::<Vec<_>>().join(",");
        let links_j = self.links.iter().map(|l| l.to_json()).collect::<Vec<_>>().join(",");
        let events_j = self.events.iter().rev().take(80).map(|e| e.to_json()).collect::<Vec<_>>().join(",");
        let srp_j = self.srp_services.iter().map(|s| s.to_json()).collect::<Vec<_>>().join(",");
        let ips_j = self.br_ipaddrs.iter().map(|a| json_str(a)).collect::<Vec<_>>().join(",");
        let scan_j = self.energy_scan.iter().map(|c| c.to_json()).collect::<Vec<_>>().join(",");
        let issues_j = self.health_issues.iter().map(|h| h.to_json()).collect::<Vec<_>>().join(",");
        let zch = self.zigbee_channel.map(|v| v.to_string()).unwrap_or_else(|| "null".to_string());
        format!(
            "{{\"updated_at_s\":{},\"demo_mode\":{},\"otbr_source\":{},\"mqtt_connected\":{},\"matter_connected\":{},\"matter_bluetooth_enabled\":{},\"matter_sdk_version\":{},\"matter_fabric_id\":{},\"zigbee_channel\":{},\"mesh_health_score\":{},\"br\":{{\"state\":{},\"network_name\":{},\"ext_pan_id\":{},\"pan_id\":{},\"channel\":{},\"rloc16\":{},\"ext_address\":{},\"rloc_address\":{},\"mesh_local_prefix\":{},\"partition_id\":{},\"leader_weight\":{},\"router_count\":{},\"srp_state\":{},\"br_state\":{},\"network_key_masked\":{},\"pskc_masked\":{},\"omr_prefix\":{},\"ipaddrs\":[{}]}},\"mac_counters\":{},\"ip_counters\":{},\"srp_services\":[{}],\"energy_scan\":[{}],\"health_issues\":[{}],\"nodes\":[{}],\"links\":[{}],\"events\":[{}]}}",
            self.updated_at_s,
            self.demo_mode,
            json_str(&self.otbr_source),
            self.mqtt_connected,
            self.matter_connected,
            self.matter_bluetooth_enabled,
            json_str(&self.matter_sdk_version),
            json_str(&self.matter_fabric_id),
            zch,
            self.mesh_health_score,
            json_str(&self.br.state),
            json_str(&self.br.network_name),
            json_str(&self.br.ext_pan_id),
            json_str(&self.br.pan_id),
            self.br.channel,
            json_str(&self.br.rloc16),
            json_str(&self.br.ext_address),
            json_str(&self.br.rloc_address),
            json_str(&self.br.mesh_local_prefix),
            self.br.partition_id,
            self.br.leader_weight,
            self.br.router_count,
            json_str(&self.br.srp_state),
            json_str(&self.br.br_state),
            json_str(&self.br.network_key_masked),
            json_str(&self.br.pskc_masked),
            json_str(&self.br_omr_prefix),
            ips_j,
            self.mac_counters.to_json(),
            self.ip_counters.to_json(),
            srp_j,
            scan_j,
            issues_j,
            nodes_j,
            links_j,
            events_j
        )
    }
}

// ============================================================================
// 3. OTBR REST API & `ot-ctl` Parsers (Compatible with default HA OTBR)
// ============================================================================

/// Parses OpenThread Border Router `GET /node` JSON payload.
pub fn parse_otbr_node_json(raw: &str, br: &mut BorderRouterInfo) {
    if let Some(v) = json_get_str(raw, "state") {
        br.state = v;
    }
    if let Some(v) = json_get_str(raw, "networkName") {
        br.network_name = v;
    }
    if let Some(v) = json_get_str(raw, "extPanId") {
        br.ext_pan_id = v;
    }
    if let Some(v) = json_get_str(raw, "rloc16") {
        br.rloc16 = normalize_rloc16(&v);
    }
    if let Some(v) = json_get_str(raw, "extAddress") {
        br.ext_address = v.to_ascii_lowercase();
    }
    if let Some(v) = json_get_str(raw, "rlocAddress") {
        br.rloc_address = v;
    }
    if let Some(v) = json_get_i64(raw, "routerCount") {
        br.router_count = v.max(0) as u32;
    }
    if let Some(v) = json_get_i64(raw, "partitionId") {
        br.partition_id = v.max(0) as u64;
    }
    if let Some(v) = json_get_i64(raw, "weighting") {
        br.leader_weight = v.max(0) as u32;
    }
}

/// Parses OpenThread Border Router `GET /node/dataset/active` JSON payload
/// and masks cryptographic keys (`networkKey`, `pskc`) at ingestion time.
pub fn parse_otbr_dataset_json(raw: &str, br: &mut BorderRouterInfo) {
    if let Some(v) = json_get_str(raw, "networkName") {
        br.network_name = v;
    }
    if let Some(v) = json_get_str(raw, "extPanId") {
        br.ext_pan_id = v;
    }
    if let Some(v) = json_get_str(raw, "meshLocalPrefix") {
        br.mesh_local_prefix = v;
    }
    if let Some(v) = json_get_i64(raw, "channel") {
        if (11..=26).contains(&v) {
            br.channel = v as u8;
        }
    }
    if let Some(v) = json_get_i64(raw, "panId") {
        br.pan_id = format!("0x{:04x}", (v as u64) & 0xffff);
    }
    if let Some(v) = json_get_str(raw, "networkKey") {
        br.network_key_masked = mask_secret_hex(&v);
    }
    if let Some(v) = json_get_str(raw, "pskc") {
        br.pskc_masked = mask_secret_hex(&v);
    }
}

pub fn normalize_rloc16(raw: &str) -> String {
    let trimmed = raw.trim().to_ascii_lowercase();
    if let Some(hex) = trimmed.strip_prefix("0x") {
        if let Ok(n) = u16::from_str_radix(hex, 16) {
            return format!("0x{:04x}", n);
        }
    } else if let Ok(n) = u16::from_str_radix(&trimmed, 16) {
        return format!("0x{:04x}", n);
    }
    trimmed
}

/// Parses `ot-ctl router table` output into Thread Router nodes.
pub fn parse_otctl_router_table(raw: &str, leader_rloc16: &str) -> Vec<ThreadNode> {
    let mut nodes = Vec::new();
    let norm_leader = normalize_rloc16(leader_rloc16);
    for line in raw.lines() {
        let l = line.trim();
        if !l.starts_with('|') || l.contains("RLOC16") {
            continue;
        }
        let cols: Vec<&str> = l.split('|').map(|c| c.trim()).filter(|c| !c.is_empty()).collect();
        if cols.len() < 8 {
            continue;
        }
        let rloc16 = normalize_rloc16(cols[1]);
        let path_cost = cols[3].parse::<u8>().unwrap_or(0);
        let lq_in = cols[4].parse::<u8>().unwrap_or(0);
        let lq_out = cols[5].parse::<u8>().unwrap_or(0);
        let age_sec = cols[6].parse::<u32>().unwrap_or(0);
        let ext_addr = cols[7].to_ascii_lowercase();
        let role = if rloc16 == norm_leader {
            ThreadRole::Leader
        } else {
            ThreadRole::Router
        };
        let default_name = if role == ThreadRole::Leader {
            format!("Border Router ({})", rloc16)
        } else {
            format!("Thread Router {}", &ext_addr[ext_addr.len().saturating_sub(4)..])
        };
        nodes.push(ThreadNode {
            rloc16,
            ext_address: ext_addr,
            friendly_name: default_name,
            role,
            lq_in,
            lq_out,
            path_cost,
            age_sec,
            ..Default::default()
        });
    }
    nodes
}

/// Parses `ot-ctl child table` output into Thread Child / SED nodes.
pub fn parse_otctl_child_table(raw: &str, parent_rloc16: &str) -> Vec<ThreadNode> {
    let mut nodes = Vec::new();
    let norm_parent = normalize_rloc16(parent_rloc16);
    for line in raw.lines() {
        let l = line.trim();
        if !l.starts_with('|') || l.contains("RLOC16") {
            continue;
        }
        let cols: Vec<&str> = l.split('|').map(|c| c.trim()).filter(|c| !c.is_empty()).collect();
        if cols.len() < 14 {
            continue;
        }
        let rloc16 = normalize_rloc16(cols[1]);
        let timeout = cols[2].parse::<u32>().unwrap_or(240);
        let age_sec = cols[3].parse::<u32>().unwrap_or(0);
        let lq_in = cols[4].parse::<u8>().unwrap_or(0);
        let rx_on_idle = cols[6] == "1";
        let version = cols[9].parse::<u8>().unwrap_or(4);
        let ext_addr = cols[13].to_ascii_lowercase();
        let is_sleepy = !rx_on_idle;
        let role = if is_sleepy {
            ThreadRole::Sed
        } else {
            ThreadRole::Child
        };
        let friendly_name = format!(
            "Thread {} {}",
            if is_sleepy { "SED" } else { "Child" },
            &ext_addr[ext_addr.len().saturating_sub(4)..]
        );
        nodes.push(ThreadNode {
            rloc16,
            ext_address: ext_addr,
            friendly_name,
            role,
            parent_rloc16: Some(norm_parent.clone()),
            avg_rssi_dbm: -75,
            last_rssi_dbm: -75,
            lq_in,
            lq_out: lq_in,
            path_cost: 1,
            age_sec,
            child_timeout_sec: timeout,
            thread_version: version,
            is_sleepy,
            ..Default::default()
        });
    }
    nodes
}

/// Enriches existing nodes (or adds missing neighbor records) using `ot-ctl neighbor table` RSSI/LQI metrics.
pub fn apply_otctl_neighbor_table(raw: &str, nodes: &mut Vec<ThreadNode>, parent_rloc16: &str) {
    let norm_parent = normalize_rloc16(parent_rloc16);
    for line in raw.lines() {
        let l = line.trim();
        if !l.starts_with('|') || l.contains("RLOC16") {
            continue;
        }
        let cols: Vec<&str> = l.split('|').map(|c| c.trim()).filter(|c| !c.is_empty()).collect();
        if cols.len() < 11 {
            continue;
        }
        let role_char = cols[0];
        let rloc16 = normalize_rloc16(cols[1]);
        let age_sec = cols[2].parse::<u32>().unwrap_or(0);
        let avg_rssi = cols[3].parse::<i32>().unwrap_or(-80);
        let last_rssi = cols[4].parse::<i32>().unwrap_or(avg_rssi);
        let lq_in = cols[5].parse::<u8>().unwrap_or(0);
        let rx_on_idle = cols[6] == "1";
        let ext_addr = cols[9].to_ascii_lowercase();
        let version = cols[10].parse::<u8>().unwrap_or(4);

        if let Some(existing) = nodes
            .iter_mut()
            .find(|n| n.ext_address == ext_addr || n.rloc16 == rloc16)
        {
            existing.avg_rssi_dbm = avg_rssi;
            existing.last_rssi_dbm = last_rssi;
            existing.lq_in = lq_in;
            existing.age_sec = age_sec;
            existing.thread_version = version;
        } else {
            let is_sleepy = !rx_on_idle && role_char.eq_ignore_ascii_case("C");
            let role = if role_char.eq_ignore_ascii_case("R") {
                ThreadRole::Router
            } else if is_sleepy {
                ThreadRole::Sed
            } else {
                ThreadRole::Child
            };
            let friendly_name = format!("Thread Node {}", &ext_addr[ext_addr.len().saturating_sub(4)..]);
            nodes.push(ThreadNode {
                rloc16,
                ext_address: ext_addr,
                friendly_name,
                role,
                parent_rloc16: Some(norm_parent.clone()),
                avg_rssi_dbm: avg_rssi,
                last_rssi_dbm: last_rssi,
                lq_in,
                lq_out: lq_in,
                path_cost: 1,
                age_sec,
                child_timeout_sec: 240,
                thread_version: version,
                is_sleepy,
                ..Default::default()
            });
        }
    }
}

/// Automatically correlates OpenThread SRP `_matter._tcp` registrations (Extended MAC -> Matter Node ID + IPv6 OMR)
/// with live `python-matter-server` L7 device nodes (Vendor, Product, Firmware, Serial, Battery, Exposes, Fabrics).
pub fn correlate_srp_and_matter(
    nodes: &mut [ThreadNode],
    srp_records: &[SrpServiceRecord],
    matter_nodes: &[LiveMatterNode],
) {
    for srp in srp_records {
        if srp.deleted || srp.ext_address.is_empty() {
            continue;
        }
        if let Some(node) = nodes.iter_mut().find(|n| n.ext_address == srp.ext_address) {
            if !srp.ipv6_omr.is_empty() {
                node.ipv6_omr = Some(srp.ipv6_omr.clone());
            }
            node.srp_service = Some(srp.instance_name.clone());
            node.srp_lease_remaining_s = Some(srp.lease_remaining_s);
            node.icd_sii_ms = srp.icd_sii_ms;
            if let Some(mid) = srp.matter_node_id {
                node.matter_node_id = Some(mid as u32);
                if let Some(mn) = matter_nodes.iter().find(|m| m.node_id == mid) {
                    node.matter_vendor = Some(mn.vendor.clone());
                    node.matter_product = Some(mn.product.clone());
                    if !mn.serial.is_empty() {
                        node.matter_serial = Some(mn.serial.clone());
                    }
                    if !mn.sw_version.is_empty() {
                        node.matter_sw_version = Some(mn.sw_version.clone());
                    }
                    if !mn.hw_version.is_empty() {
                        node.matter_hw_version = Some(mn.hw_version.clone());
                    }
                    node.matter_available = mn.available;
                    node.matter_state = Some(mn.state_summary.clone());
                    node.matter_clusters = mn.clusters.clone();
                    node.battery_pct = mn.battery_pct;
                    node.battery_mv = mn.battery_mv;
                    node.battery_type = mn.battery_type.clone();
                    node.exposes = mn.exposes.clone();
                    node.fabrics = mn.fabrics.clone();
                    // Upgrade generic fallback name to human-readable Matter identity
                    if node.friendly_name.starts_with("Thread ") {
                        if !mn.node_label.is_empty() {
                            node.friendly_name = mn.node_label.clone();
                        } else {
                            node.friendly_name = format!("{} {} (#{})", mn.vendor, mn.product, mn.node_id);
                        }
                    }
                }
            }
        }
    }
    for n in nodes.iter_mut() {
        n.health_score = compute_node_health_score(n);
    }
}

/// Correlates Matter L7 devices onto their physical Thread L2/L3 mesh nodes by Extended MAC.
pub fn correlate_matter_nodes(nodes: &mut [ThreadNode], matter_devices: &[MatterDeviceSummary]) {
    for md in matter_devices {
        let target_ext = md.ext_address.trim().to_ascii_lowercase();
        if let Some(node) = nodes.iter_mut().find(|n| n.ext_address == target_ext) {
            node.matter_node_id = Some(md.node_id);
            node.matter_vendor = Some(md.vendor.clone());
            node.matter_product = Some(md.product.clone());
            node.matter_state = Some(md.state_summary.clone());
            node.matter_clusters = md.clusters.clone();
        }
    }
}

/// Derives topology edges from parent-child & router relationships.
pub fn rebuild_mesh_links(nodes: &[ThreadNode], leader_rloc16: &str) -> Vec<MeshLink> {
    let mut links = Vec::new();
    let norm_leader = normalize_rloc16(leader_rloc16);
    for n in nodes {
        if n.rloc16 == norm_leader {
            continue;
        }
        let parent = n.parent_rloc16.clone().unwrap_or_else(|| norm_leader.clone());
        links.push(MeshLink {
            source_rloc16: parent,
            target_rloc16: n.rloc16.clone(),
            rssi_dbm: n.avg_rssi_dbm,
            lqi: n.lq_in,
            quality: n.signal_quality().to_string(),
        });
    }
    links
}

/// Minimal pure-std HTTP/1.1 GET helper for querying OTBR REST API (`http://host:port/path`).
pub fn fetch_http_json(base_url: &str, path: &str, timeout_ms: u64) -> Result<String, String> {
    let stripped = base_url
        .trim()
        .strip_prefix("http://")
        .ok_or_else(|| "Only plain local http:// OTBR endpoints are supported".to_string())?;
    let host_port = stripped.split('/').next().unwrap_or(stripped);
    let addr = if host_port.contains(':') {
        host_port.to_string()
    } else {
        format!("{}:80", host_port)
    };
    let mut stream = TcpStream::connect(&addr).map_err(|e| format!("OTBR connect {} KO: {}", addr, e))?;
    let dur = Some(Duration::from_millis(timeout_ms));
    let _ = stream.set_read_timeout(dur);
    let _ = stream.set_write_timeout(dur);
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        path, host_port
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("OTBR write KO: {}", e))?;
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|e| format!("OTBR read KO: {}", e))?;
    let text = String::from_utf8_lossy(&raw).to_string();
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| "Malformed HTTP response from OTBR".to_string())?;
    if !head.starts_with("HTTP/1.1 200") && !head.starts_with("HTTP/1.0 200") {
        return Err(format!("OTBR {} returned non-200: {}", path, head.lines().next().unwrap_or("")));
    }
    Ok(body.trim().to_string())
}

// ============================================================================
// 4. Pure-Rust MQTT 3.1.1 Wire Codec + Home Assistant Auto-Discovery
// ============================================================================

pub fn encode_mqtt_remaining_length(mut len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (len % 128) as u8;
        len /= 128;
        if len > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if len == 0 {
            break;
        }
    }
    out
}

fn push_mqtt_str(buf: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    buf.push(((b.len() >> 8) & 0xff) as u8);
    buf.push((b.len() & 0xff) as u8);
    buf.extend_from_slice(b);
}

pub fn encode_mqtt_connect(
    client_id: &str,
    username: Option<&str>,
    password: Option<&str>,
    will_topic: Option<&str>,
    will_payload: Option<&str>,
    keepalive_s: u16,
) -> Vec<u8> {
    let mut vh = Vec::new();
    push_mqtt_str(&mut vh, "MQTT");
    vh.push(4); // MQTT 3.1.1
    let mut flags: u8 = 0x02; // Clean Session
    if will_topic.is_some() && will_payload.is_some() {
        flags |= 0x04 | 0x20; // Will Flag + Will Retain
    }
    if username.is_some() {
        flags |= 0x80;
    }
    if password.is_some() {
        flags |= 0x40;
    }
    vh.push(flags);
    vh.push(((keepalive_s >> 8) & 0xff) as u8);
    vh.push((keepalive_s & 0xff) as u8);

    let mut pl = Vec::new();
    push_mqtt_str(&mut pl, client_id);
    if let (Some(wt), Some(wp)) = (will_topic, will_payload) {
        push_mqtt_str(&mut pl, wt);
        push_mqtt_str(&mut pl, wp);
    }
    if let Some(u) = username {
        push_mqtt_str(&mut pl, u);
    }
    if let Some(p) = password {
        push_mqtt_str(&mut pl, p);
    }

    let mut pkt = Vec::with_capacity(2 + vh.len() + pl.len());
    pkt.push(0x10); // CONNECT
    pkt.extend_from_slice(&encode_mqtt_remaining_length(vh.len() + pl.len()));
    pkt.extend_from_slice(&vh);
    pkt.extend_from_slice(&pl);
    pkt
}

pub fn encode_mqtt_publish(topic: &str, payload: &str, retain: bool) -> Vec<u8> {
    let safe_payload = sanitize_mqtt_payload(payload);
    let mut body = Vec::with_capacity(2 + topic.len() + safe_payload.len());
    push_mqtt_str(&mut body, topic);
    body.extend_from_slice(safe_payload.as_bytes());
    let mut pkt = Vec::with_capacity(2 + body.len());
    pkt.push(if retain { 0x31 } else { 0x30 }); // QoS 0 PUBLISH
    pkt.extend_from_slice(&encode_mqtt_remaining_length(body.len()));
    pkt.extend_from_slice(&body);
    pkt
}

pub fn encode_mqtt_pingreq() -> [u8; 2] {
    [0xC0, 0x00]
}

pub struct MqttPublisher {
    stream: TcpStream,
}

impl MqttPublisher {
    pub fn connect(
        addr: &str,
        client_id: &str,
        username: Option<&str>,
        password: Option<&str>,
        base_topic: &str,
    ) -> Result<Self, String> {
        let mut stream = TcpStream::connect(addr).map_err(|e| format!("MQTT TCP {} KO: {}", addr, e))?;
        let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
        let will_topic = format!("{}/bridge/state", base_topic);
        let pkt = encode_mqtt_connect(client_id, username, password, Some(&will_topic), Some("offline"), 60);
        stream
            .write_all(&pkt)
            .map_err(|e| format!("MQTT CONNECT write KO: {}", e))?;
        let mut ack = [0u8; 4];
        stream
            .read_exact(&mut ack)
            .map_err(|e| format!("MQTT CONNACK read KO: {}", e))?;
        if ack[0] != 0x20 || ack[3] != 0x00 {
            return Err(format!("MQTT CONNACK rejected: code={}", ack[3]));
        }
        Ok(Self { stream })
    }

    pub fn publish(&mut self, topic: &str, payload: &str, retain: bool) -> Result<(), String> {
        let pkt = encode_mqtt_publish(topic, payload, retain);
        self.stream
            .write_all(&pkt)
            .map_err(|e| format!("MQTT PUBLISH {} KO: {}", topic, e))
    }

    pub fn ping(&mut self) -> Result<(), String> {
        self.stream
            .write_all(&encode_mqtt_pingreq())
            .map_err(|e| format!("MQTT PING KO: {}", e))
    }
}

/// Generates 100% compliant Home Assistant MQTT Auto-Discovery payloads for the
/// Thread Border Router + every discovered Thread/Matter node.
pub fn build_ha_discovery_payloads(
    discovery_prefix: &str,
    base_topic: &str,
    snapshot: &MeshSnapshot,
) -> Vec<(String, String)> {
    let dp = discovery_prefix.trim_end_matches('/');
    let bt = base_topic.trim_end_matches('/');
    let mut out = Vec::new();
    let br_ident = format!("thread2mqtt_br_{}", snapshot.br.ext_address);
    let br_dev = format!(
        "{{\"identifiers\":[{}],\"name\":{},\"manufacturer\":\"OpenThread / Thread2MQTT Rust\",\"model\":\"OpenThread Border Router (CH {})\",\"sw_version\":{}}}",
        json_str(&br_ident),
        json_str(&format!("Thread2MQTT Border Router ({})", snapshot.br.network_name)),
        snapshot.br.channel,
        json_str(env!("CARGO_PKG_VERSION"))
    );
    let avail = format!("{}/bridge/state", bt);

    // 1. Bridge Online Binary Sensor
    out.push((
        format!("{}/binary_sensor/thread2mqtt_bridge_state/config", dp),
        format!(
            "{{\"name\":\"Thread2MQTT Bridge\",\"unique_id\":\"thread2mqtt_bridge_state\",\"state_topic\":{},\"payload_on\":\"online\",\"payload_off\":\"offline\",\"device_class\":\"connectivity\",\"entity_category\":\"diagnostic\",\"device\":{}}}",
            json_str(&avail),
            br_dev
        ),
    ));

    // 2. Mesh Node Count Sensor
    out.push((
        format!("{}/sensor/thread2mqtt_mesh_nodes/config", dp),
        format!(
            "{{\"name\":\"Thread Mesh Nodes\",\"unique_id\":\"thread2mqtt_mesh_nodes\",\"state_topic\":{},\"value_template\":\"{{{{ value_json.nodes_count }}}}\",\"availability_topic\":{},\"icon\":\"mdi:lan\",\"state_class\":\"measurement\",\"entity_category\":\"diagnostic\",\"device\":{}}}",
            json_str(&format!("{}/bridge/info", bt)),
            json_str(&avail),
            br_dev
        ),
    ));

    // 3. Per-Node RSSI, LQI & Role Diagnostic Entities (grouped under each Thread/Matter device)
    for node in &snapshot.nodes {
        let slug = sanitize_topic_slug(&node.ext_address);
        let state_topic = format!("{}/node/{}", bt, slug);
        let dev_ident = format!("thread2mqtt_node_{}", slug);
        let model = node
            .matter_product
            .as_deref()
            .unwrap_or(match node.role {
                ThreadRole::Leader => "Thread Border Router (Leader)",
                ThreadRole::Router => "Thread Mesh Router (FTD)",
                ThreadRole::Sed => "Thread Sleepy End Device (SED)",
                _ => "Thread End Device (MTD)",
            });
        let vendor = node.matter_vendor.as_deref().unwrap_or("OpenThread Mesh");
        let node_dev = format!(
            "{{\"identifiers\":[{}],\"via_device\":{},\"name\":{},\"manufacturer\":{},\"model\":{}}}",
            json_str(&dev_ident),
            json_str(&br_ident),
            json_str(&node.friendly_name),
            json_str(vendor),
            json_str(model)
        );

        // RSSI (dBm)
        out.push((
            format!("{}/sensor/thread2mqtt_{}_rssi/config", dp, slug),
            format!(
                "{{\"name\":\"Thread RSSI\",\"unique_id\":\"thread2mqtt_{}_rssi\",\"state_topic\":{},\"value_template\":\"{{{{ value_json.avg_rssi_dbm }}}}\",\"unit_of_measurement\":\"dBm\",\"device_class\":\"signal_strength\",\"state_class\":\"measurement\",\"entity_category\":\"diagnostic\",\"availability_topic\":{},\"device\":{}}}",
                slug,
                json_str(&state_topic),
                json_str(&avail),
                node_dev
            ),
        ));

        // LQI In (0-3)
        out.push((
            format!("{}/sensor/thread2mqtt_{}_lqi/config", dp, slug),
            format!(
                "{{\"name\":\"Thread Link Quality\",\"unique_id\":\"thread2mqtt_{}_lqi\",\"state_topic\":{},\"value_template\":\"{{{{ value_json.lq_in }}}}\",\"icon\":\"mdi:signal-cellular-3\",\"state_class\":\"measurement\",\"entity_category\":\"diagnostic\",\"availability_topic\":{},\"device\":{}}}",
                slug,
                json_str(&state_topic),
                json_str(&avail),
                node_dev
            ),
        ));

        // Mesh Role
        out.push((
            format!("{}/sensor/thread2mqtt_{}_role/config", dp, slug),
            format!(
                "{{\"name\":\"Thread Role\",\"unique_id\":\"thread2mqtt_{}_role\",\"state_topic\":{},\"value_template\":\"{{{{ value_json.role }}}}\",\"icon\":\"mdi:access-point-network\",\"entity_category\":\"diagnostic\",\"availability_topic\":{},\"device\":{}}}",
                slug,
                json_str(&state_topic),
                json_str(&avail),
                node_dev
            ),
        ));
    }
    out
}

pub fn sanitize_topic_slug(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Validates and cleans a user-supplied friendly name (prevents XSS / control chars).
pub fn sanitize_friendly_name(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .trim()
        .chars()
        .filter(|c| !c.is_control() && *c != '<' && *c != '>' && *c != '"')
        .take(64)
        .collect();
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

// ============================================================================
// 5. Prometheus /metrics Exposition
// ============================================================================

pub fn render_prometheus_metrics(snapshot: &MeshSnapshot) -> String {
    let mut out = String::with_capacity(4096);
    out.push_str("# HELP thread2mqtt_up Thread2MQTT daemon availability (1=up)\n");
    out.push_str("# TYPE thread2mqtt_up gauge\n");
    out.push_str("thread2mqtt_up 1\n");
    out.push_str("# HELP thread2mqtt_mesh_nodes_total Total Thread mesh nodes discovered\n");
    out.push_str("# TYPE thread2mqtt_mesh_nodes_total gauge\n");
    out.push_str(&format!("thread2mqtt_mesh_nodes_total {}\n", snapshot.nodes.len()));
    out.push_str("# HELP thread2mqtt_router_count Active Thread routers in partition\n");
    out.push_str("# TYPE thread2mqtt_router_count gauge\n");
    out.push_str(&format!("thread2mqtt_router_count {}\n", snapshot.br.router_count));
    out.push_str("# HELP thread2mqtt_channel Active IEEE 802.15.4 Thread RF channel\n");
    out.push_str("# TYPE thread2mqtt_channel gauge\n");
    out.push_str(&format!("thread2mqtt_channel {}\n", snapshot.br.channel));
    out.push_str("# HELP thread2mqtt_mesh_health_score Overall Thread+Matter mesh health score (0-100)\n");
    out.push_str("# TYPE thread2mqtt_mesh_health_score gauge\n");
    out.push_str(&format!("thread2mqtt_mesh_health_score {}\n", snapshot.mesh_health_score));
    out.push_str("# HELP thread2mqtt_mac_tx_total Total 802.15.4 MAC TX frames\n");
    out.push_str("# TYPE thread2mqtt_mac_tx_total counter\n");
    out.push_str(&format!("thread2mqtt_mac_tx_total {}\n", snapshot.mac_counters.tx_total));
    out.push_str("# HELP thread2mqtt_mac_rx_total Total 802.15.4 MAC RX frames\n");
    out.push_str("# TYPE thread2mqtt_mac_rx_total counter\n");
    out.push_str(&format!("thread2mqtt_mac_rx_total {}\n", snapshot.mac_counters.rx_total));
    out.push_str("# HELP thread2mqtt_mac_cca_errors_total 802.15.4 CCA busy-channel errors\n");
    out.push_str("# TYPE thread2mqtt_mac_cca_errors_total counter\n");
    out.push_str(&format!("thread2mqtt_mac_cca_errors_total {}\n", snapshot.mac_counters.tx_err_cca));
    out.push_str("# HELP thread2mqtt_mac_ack_rate_percent 802.15.4 MAC ACK success percentage (0-100)\n");
    out.push_str("# TYPE thread2mqtt_mac_ack_rate_percent gauge\n");
    out.push_str(&format!("thread2mqtt_mac_ack_rate_percent {:.2}\n", snapshot.mac_counters.ack_rate_pct()));
    out.push_str("# HELP thread2mqtt_ip_delivery_ratio IPv6 packet delivery rate percentage (0-100)\n");
    out.push_str("# TYPE thread2mqtt_ip_delivery_ratio gauge\n");
    out.push_str(&format!("thread2mqtt_ip_delivery_ratio {:.2}\n", snapshot.ip_counters.delivery_rate_pct()));
    out.push_str("# HELP thread2mqtt_node_rssi_dbm Average Thread radio RSSI per node (dBm)\n");
    out.push_str("# TYPE thread2mqtt_node_rssi_dbm gauge\n");
    for n in &snapshot.nodes {
        let lbl = format!(
            "rloc16=\"{}\",ext_address=\"{}\",name=\"{}\",role=\"{}\"",
            json_escape(&n.rloc16),
            json_escape(&n.ext_address),
            json_escape(&n.friendly_name),
            n.role.as_str()
        );
        out.push_str(&format!("thread2mqtt_node_rssi_dbm{{{}}} {}\n", lbl, n.avg_rssi_dbm));
    }
    out.push_str("# HELP thread2mqtt_node_lqi_in Incoming Thread Link Quality Indicator (0-3)\n");
    out.push_str("# TYPE thread2mqtt_node_lqi_in gauge\n");
    for n in &snapshot.nodes {
        let lbl = format!(
            "rloc16=\"{}\",ext_address=\"{}\",name=\"{}\",role=\"{}\"",
            json_escape(&n.rloc16),
            json_escape(&n.ext_address),
            json_escape(&n.friendly_name),
            n.role.as_str()
        );
        out.push_str(&format!("thread2mqtt_node_lqi_in{{{}}} {}\n", lbl, n.lq_in));
    }
    out.push_str("# HELP thread2mqtt_node_health_score Per-node Thread/Matter health score (0-100)\n");
    out.push_str("# TYPE thread2mqtt_node_health_score gauge\n");
    for n in &snapshot.nodes {
        let lbl = format!(
            "rloc16=\"{}\",ext_address=\"{}\",name=\"{}\"",
            json_escape(&n.rloc16),
            json_escape(&n.ext_address),
            json_escape(&n.friendly_name)
        );
        out.push_str(&format!("thread2mqtt_node_health_score{{{}}} {}\n", lbl, n.health_score));
    }
    out.push_str("# HELP thread2mqtt_node_battery_percent Matter PowerSource battery percentage\n");
    out.push_str("# TYPE thread2mqtt_node_battery_percent gauge\n");
    for n in &snapshot.nodes {
        if let Some(pct) = n.battery_pct {
            let lbl = format!(
                "rloc16=\"{}\",ext_address=\"{}\",name=\"{}\"",
                json_escape(&n.rloc16),
                json_escape(&n.ext_address),
                json_escape(&n.friendly_name)
            );
            out.push_str(&format!("thread2mqtt_node_battery_percent{{{}}} {}\n", lbl, pct));
        }
    }
    out.push_str("# HELP thread2mqtt_node_matter_available Matter L7 CASE reachability (1=online, 0=offline)\n");
    out.push_str("# TYPE thread2mqtt_node_matter_available gauge\n");
    for n in &snapshot.nodes {
        if n.matter_node_id.is_some() {
            let lbl = format!(
                "rloc16=\"{}\",ext_address=\"{}\",name=\"{}\"",
                json_escape(&n.rloc16),
                json_escape(&n.ext_address),
                json_escape(&n.friendly_name)
            );
            out.push_str(&format!(
                "thread2mqtt_node_matter_available{{{}}} {}\n",
                lbl,
                if n.matter_available { 1 } else { 0 }
            ));
        }
    }
    out.push_str("# HELP thread2mqtt_node_srp_lease_seconds Remaining OpenThread SRP _matter._tcp lease in seconds\n");
    out.push_str("# TYPE thread2mqtt_node_srp_lease_seconds gauge\n");
    for n in &snapshot.nodes {
        if let Some(lease) = n.srp_lease_remaining_s {
            let lbl = format!(
                "rloc16=\"{}\",ext_address=\"{}\",name=\"{}\"",
                json_escape(&n.rloc16),
                json_escape(&n.ext_address),
                json_escape(&n.friendly_name)
            );
            out.push_str(&format!("thread2mqtt_node_srp_lease_seconds{{{}}} {}\n", lbl, lease));
        }
    }
    out
}

// ============================================================================
// 6. Synthetic Zero-Leakage Demo Mesh (RFC 5737 / Example IDs Only)
// ============================================================================

pub fn build_demo_snapshot() -> MeshSnapshot {
    let br = BorderRouterInfo {
        state: "leader".to_string(),
        network_name: "HomeLab-Thread-Demo".to_string(),
        ext_pan_id: "deadbeef00001111".to_string(),
        pan_id: "0xabcd".to_string(),
        channel: 25,
        rloc16: "0x6c00".to_string(),
        ext_address: "0200000000000001".to_string(),
        rloc_address: "fd00:db8:1234::ff:fe00:6c00".to_string(),
        mesh_local_prefix: "fd00:db8:1234::/64".to_string(),
        partition_id: 104857601,
        leader_weight: 65,
        router_count: 3,
        srp_state: "running".to_string(),
        br_state: "running".to_string(),
        network_key_masked: "****...cafe".to_string(),
        pskc_masked: "****...babe".to_string(),
    };

    let demo_fabric = vec![
        MatterFabricInfo { fabric_index: 1, vendor_id: 4939, label: "Home Assistant".to_string(), node_id: 12 },
        MatterFabricInfo { fabric_index: 2, vendor_id: 4937, label: "Apple Home".to_string(), node_id: 12 },
    ];

    let mut nodes = vec![
        ThreadNode {
            rloc16: "0x6c00".to_string(),
            ext_address: "0200000000000001".to_string(),
            friendly_name: "OTBR Leader (PoE EFR32MG26)".to_string(),
            role: ThreadRole::Leader,
            lq_in: 3,
            lq_out: 3,
            ipv6_omr: Some("fd00:db8:cafe:1::1".to_string()),
            matter_vendor: Some("OpenThread".to_string()),
            matter_product: Some("Border Router 1.4".to_string()),
            matter_sw_version: Some("OTBR 2026.1".to_string()),
            matter_state: Some("Leader · SRP running".to_string()),
            matter_clusters: vec!["ThreadNetworkDiagnostics".to_string()],
            group: Some("Infrastructure".to_string()),
            description: Some("Primary PoE Thread Border Router".to_string()),
            ..Default::default()
        },
        ThreadNode {
            rloc16: "0x1400".to_string(),
            ext_address: "0200000000000002".to_string(),
            friendly_name: "Living Room Plug (Router)".to_string(),
            role: ThreadRole::Router,
            parent_rloc16: Some("0x6c00".to_string()),
            avg_rssi_dbm: -56,
            last_rssi_dbm: -55,
            lq_in: 3,
            lq_out: 3,
            path_cost: 1,
            age_sec: 4,
            ipv6_omr: Some("fd00:db8:cafe:1::12".to_string()),
            srp_service: Some("CAFE0001-000000000000000C._matter._tcp".to_string()),
            srp_lease_remaining_s: Some(5420),
            matter_node_id: Some(12),
            matter_vendor: Some("Eve Systems".to_string()),
            matter_product: Some("Eve Energy Matter".to_string()),
            matter_serial: Some("DEMO-EVE-0012".to_string()),
            matter_sw_version: Some("3.2.1".to_string()),
            matter_hw_version: Some("1.0".to_string()),
            matter_state: Some("ON · 42.6 W".to_string()),
            matter_clusters: vec!["OnOff".to_string(), "ElectricalPowerMeasurement".to_string(), "Identify".to_string()],
            exposes: vec![
                MatterExpose { name: "Switch State".into(), property: "state".into(), value: "ON".into(), unit: "".into(), cluster: "0x0006 OnOff".into(), access: "RW".into() },
                MatterExpose { name: "Active Power".into(), property: "power".into(), value: "42.6".into(), unit: "W".into(), cluster: "0x0090 Power".into(), access: "R".into() },
            ],
            fabrics: demo_fabric.clone(),
            group: Some("Living Room".to_string()),
            ..Default::default()
        },
        ThreadNode {
            rloc16: "0x2800".to_string(),
            ext_address: "0200000000000003".to_string(),
            friendly_name: "Hallway Ceiling Bulb (Router)".to_string(),
            role: ThreadRole::Router,
            parent_rloc16: Some("0x6c00".to_string()),
            avg_rssi_dbm: -64,
            last_rssi_dbm: -63,
            lq_in: 3,
            lq_out: 3,
            path_cost: 1,
            age_sec: 7,
            ipv6_omr: Some("fd00:db8:cafe:1::15".to_string()),
            srp_service: Some("CAFE0001-000000000000000F._matter._tcp".to_string()),
            srp_lease_remaining_s: Some(4910),
            matter_node_id: Some(15),
            matter_vendor: Some("Nanoleaf".to_string()),
            matter_product: Some("Essentials A60 Matter".to_string()),
            matter_serial: Some("DEMO-NL-0015".to_string()),
            matter_sw_version: Some("3.6.196".to_string()),
            matter_hw_version: Some("2.0".to_string()),
            matter_state: Some("ON · 80% · 4000K".to_string()),
            matter_clusters: vec!["OnOff".to_string(), "LevelControl".to_string(), "ColorControl".to_string()],
            exposes: vec![
                MatterExpose { name: "Light".into(), property: "state".into(), value: "ON".into(), unit: "".into(), cluster: "0x0006 OnOff".into(), access: "RW".into() },
                MatterExpose { name: "Brightness".into(), property: "brightness".into(), value: "80".into(), unit: "%".into(), cluster: "0x0008 Level".into(), access: "RW".into() },
            ],
            fabrics: vec![demo_fabric[0].clone()],
            group: Some("Hallway".to_string()),
            ..Default::default()
        },
        ThreadNode {
            rloc16: "0x6c01".to_string(),
            ext_address: "0200000000000004".to_string(),
            friendly_name: "Office Climate Sensor".to_string(),
            role: ThreadRole::Sed,
            parent_rloc16: Some("0x6c00".to_string()),
            avg_rssi_dbm: -69,
            last_rssi_dbm: -70,
            lq_in: 3,
            lq_out: 3,
            path_cost: 1,
            age_sec: 14,
            child_timeout_sec: 240,
            is_sleepy: true,
            ipv6_omr: Some("fd00:db8:cafe:1::18".to_string()),
            srp_service: Some("CAFE0001-0000000000000012._matter._tcp".to_string()),
            srp_lease_remaining_s: Some(3610),
            icd_sii_ms: Some(15000),
            matter_node_id: Some(18),
            matter_vendor: Some("Aqara".to_string()),
            matter_product: Some("Climate Sensor W100".to_string()),
            matter_serial: Some("DEMO-AQ-0018".to_string()),
            matter_sw_version: Some("1.0.4".to_string()),
            matter_hw_version: Some("1.0".to_string()),
            matter_state: Some("21.4°C · 49% RH · Bat 94%".to_string()),
            matter_clusters: vec!["TemperatureMeasurement".to_string(), "RelativeHumidity".to_string(), "PowerSource".to_string()],
            battery_pct: Some(94),
            battery_mv: Some(2980),
            battery_type: Some("CR2450".to_string()),
            exposes: vec![
                MatterExpose { name: "Temperature".into(), property: "temperature".into(), value: "21.4".into(), unit: "°C".into(), cluster: "0x0402 Temp".into(), access: "R".into() },
                MatterExpose { name: "Humidity".into(), property: "humidity".into(), value: "49".into(), unit: "%".into(), cluster: "0x0405 RH".into(), access: "R".into() },
                MatterExpose { name: "Battery".into(), property: "battery".into(), value: "94".into(), unit: "%".into(), cluster: "0x002F Power".into(), access: "R".into() },
            ],
            fabrics: vec![demo_fabric[0].clone()],
            group: Some("Office".to_string()),
            ..Default::default()
        },
        ThreadNode {
            rloc16: "0x1401".to_string(),
            ext_address: "0200000000000005".to_string(),
            friendly_name: "Front Door Contact (SED)".to_string(),
            role: ThreadRole::Sed,
            parent_rloc16: Some("0x1400".to_string()),
            avg_rssi_dbm: -74,
            last_rssi_dbm: -73,
            lq_in: 2,
            lq_out: 3,
            path_cost: 2,
            age_sec: 21,
            child_timeout_sec: 240,
            is_sleepy: true,
            ipv6_omr: Some("fd00:db8:cafe:1::21".to_string()),
            srp_service: Some("CAFE0001-0000000000000015._matter._tcp".to_string()),
            srp_lease_remaining_s: Some(3480),
            icd_sii_ms: Some(17000),
            matter_node_id: Some(21),
            matter_vendor: Some("Aqara".to_string()),
            matter_product: Some("Door & Window P2".to_string()),
            matter_serial: Some("DEMO-AQ-0021".to_string()),
            matter_sw_version: Some("1.0.2".to_string()),
            matter_hw_version: Some("1.0".to_string()),
            matter_state: Some("Closed · Bat 88%".to_string()),
            matter_clusters: vec!["BooleanState".to_string(), "PowerSource".to_string()],
            battery_pct: Some(88),
            battery_mv: Some(2940),
            battery_type: Some("CR123A".to_string()),
            exposes: vec![
                MatterExpose { name: "Contact".into(), property: "contact".into(), value: "Closed".into(), unit: "".into(), cluster: "0x0045 Contact".into(), access: "R".into() },
                MatterExpose { name: "Battery".into(), property: "battery".into(), value: "88".into(), unit: "%".into(), cluster: "0x002F Power".into(), access: "R".into() },
            ],
            fabrics: demo_fabric.clone(),
            group: Some("Security".to_string()),
            ..Default::default()
        },
        ThreadNode {
            rloc16: "0x2801".to_string(),
            ext_address: "0200000000000006".to_string(),
            friendly_name: "Garden Shed Smoke & Motion".to_string(),
            role: ThreadRole::Sed,
            parent_rloc16: Some("0x2800".to_string()),
            avg_rssi_dbm: -86,
            last_rssi_dbm: -88,
            lq_in: 2,
            lq_out: 2,
            path_cost: 2,
            age_sec: 39,
            child_timeout_sec: 240,
            is_sleepy: true,
            ipv6_omr: Some("fd00:db8:cafe:1::24".to_string()),
            srp_service: Some("CAFE0001-0000000000000018._matter._tcp".to_string()),
            srp_lease_remaining_s: Some(2890),
            icd_sii_ms: Some(17000),
            matter_node_id: Some(24),
            matter_vendor: Some("Eve Systems".to_string()),
            matter_product: Some("Eve Motion Matter".to_string()),
            matter_serial: Some("DEMO-EVE-0024".to_string()),
            matter_sw_version: Some("3.2.0".to_string()),
            matter_hw_version: Some("1.0".to_string()),
            matter_state: Some("Clear · 142 lx · Bat 79%".to_string()),
            matter_clusters: vec!["OccupancySensing".to_string(), "IlluminanceMeasurement".to_string(), "PowerSource".to_string()],
            battery_pct: Some(79),
            battery_mv: Some(2870),
            battery_type: Some("AAA x2".to_string()),
            exposes: vec![
                MatterExpose { name: "Occupancy".into(), property: "occupancy".into(), value: "Clear".into(), unit: "".into(), cluster: "0x0406 Occupancy".into(), access: "R".into() },
                MatterExpose { name: "Battery".into(), property: "battery".into(), value: "79".into(), unit: "%".into(), cluster: "0x002F Power".into(), access: "R".into() },
            ],
            fabrics: vec![demo_fabric[0].clone()],
            group: Some("Security".to_string()),
            ..Default::default()
        },
    ];

    for (idx, n) in nodes.iter_mut().enumerate() {
        n.health_score = compute_node_health_score(n);
        if n.role != ThreadRole::Leader && n.avg_rssi_dbm < 0 {
            let base = n.avg_rssi_dbm;
            n.rssi_history = (0..18)
                .map(|i| {
                    let wave = ((i as i32 * 3 + idx as i32 * 5) % 5) - 2;
                    (base + wave).clamp(-96, -35)
                })
                .collect();
        }
    }
    let links = rebuild_mesh_links(&nodes, &br.rloc16);
    let mut friendly_names = BTreeMap::new();
    for n in &nodes {
        friendly_names.insert(n.ext_address.clone(), n.friendly_name.clone());
    }
    let mac_counters = MacCounters {
        tx_total: 42180,
        tx_unicast: 8420,
        tx_broadcast: 33760,
        tx_ack_requested: 8400,
        tx_acked: 8342,
        tx_retry: 12,
        tx_err_cca: 3,
        tx_err_busy_channel: 3,
        tx_err_abort: 0,
        tx_direct_max_retry_expiry: 2,
        tx_indirect_max_retry_expiry: 18,
        rx_total: 39410,
        rx_unicast: 39120,
        rx_data_poll: 28900,
        rx_duplicated: 41,
        rx_err_fcs: 0,
        rx_err_sec: 0,
    };
    let ip_counters = IpCounters {
        tx_success: 18920,
        tx_failed: 14,
        rx_success: 6410,
        rx_failed: 2,
    };
    let energy_scan: Vec<EnergyScanChannel> = (11..=26)
        .map(|ch| {
            let rssi = match ch {
                11 => -88, 12 => -69, 13 => -65, 14 => -72, 15 => -86,
                16 => -84, 17 => -64, 18 => -61, 19 => -67, 20 => -85,
                21 => -83, 22 => -66, 23 => -63, 24 => -70, 25 => -93, 26 => -91,
                _ => -85,
            };
            EnergyScanChannel { channel: ch, max_rssi_dbm: rssi }
        })
        .collect();
    let (mesh_health_score, health_issues) = analyze_mesh_health(&br, &nodes, &mac_counters, &ip_counters, Some(11));

    let mut snap = MeshSnapshot {
        updated_at_s: now_epoch_s(),
        demo_mode: true,
        otbr_source: "synthetic-demo (Thread 1.4 + SRP + Matter L7)".to_string(),
        mqtt_connected: false,
        matter_connected: true,
        matter_bluetooth_enabled: true,
        matter_sdk_version: "2025.7.0".to_string(),
        matter_fabric_id: "CAFE000100000001".to_string(),
        zigbee_channel: Some(11),
        br,
        br_ipaddrs: vec![
            "fd00:db8:1234::ff:fe00:6c00".to_string(),
            "fd00:db8:cafe:1::1".to_string(),
            "fe80::200:ff:fe00:1".to_string(),
        ],
        br_omr_prefix: "fd00:db8:cafe:1::/64".to_string(),
        mac_counters,
        ip_counters,
        srp_services: nodes
            .iter()
            .filter_map(|n| {
                n.srp_service.as_ref().map(|svc| SrpServiceRecord {
                    instance_name: svc.clone(),
                    fabric_id: "CAFE000100000001".to_string(),
                    matter_node_id: n.matter_node_id.map(|x| x as u64),
                    ext_address: n.ext_address.clone(),
                    ipv6_omr: n.ipv6_omr.clone().unwrap_or_default(),
                    port: 5540,
                    lease_remaining_s: n.srp_lease_remaining_s.unwrap_or(3600),
                    icd_sii_ms: n.icd_sii_ms,
                    icd_sai_ms: Some(3000),
                    deleted: false,
                })
            })
            .collect(),
        energy_scan,
        mesh_health_score,
        health_issues,
        nodes,
        links,
        friendly_names,
        node_meta: BTreeMap::new(),
        rssi_history_map: BTreeMap::new(),
        events: Vec::new(),
    };
    snap.push_event(
        "INFO",
        "OTBR",
        "Synthetic Thread 1.4 demo mesh initialized (CH 25 · 6 nodes · 3 routers)",
        "{\"channel\":25,\"routers\":3,\"children\":3}",
    );
    snap.push_event(
        "INFO",
        "MATTER",
        "Correlated 5 Matter-over-Thread endpoints via SRP onto L2/L3 RLOC16 topology",
        "{\"correlated\":5,\"clusters\":[\"OnOff\",\"TemperatureMeasurement\",\"BooleanState\"]}",
    );
    snap.push_event(
        "INFO",
        "MQTT",
        "Home Assistant MQTT Auto-Discovery schemas ready (20 diagnostic entities)",
        "{\"discovery_prefix\":\"homeassistant\",\"entities\":20}",
    );
    snap
}

// ============================================================================
// 7. Unit Tests (100% deterministic, run with `cargo test`)
// ============================================================================

/// Read-only local hardware & service detector (Zero-Trust: no docker.sock, no shell, passive /sys & loopback probe).
pub fn scan_local_hardware(demo_mode: bool, matter_bluetooth_enabled: bool) -> String {
    if demo_mode {
        return "{\"demo\":true,\"matter_bluetooth_enabled\":true,\"bluetooth_adapters\":[{\"name\":\"hci0\",\"index\":0,\"status\":\"ready\"}],\"serial_devices\":[{\"name\":\"usb-SMLIGHT_SLZB-MR4U_Thread_RCP-if00\",\"path\":\"/dev/serial/by-id/usb-SMLIGHT_SLZB-MR4U_Thread_RCP-if00\"}],\"local_services\":[{\"name\":\"python-matter-server\",\"endpoint\":\"127.0.0.1:5580\",\"reachable\":true},{\"name\":\"otbr-agent REST\",\"endpoint\":\"127.0.0.1:8081\",\"reachable\":true}]}".to_string();
    }

    let mut bt_items: Vec<String> = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/sys/class/bluetooth") {
        let mut names: Vec<String> = entries
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.starts_with("hci"))
            .collect();
        names.sort();
        for n in names {
            let idx = n.trim_start_matches("hci").parse::<u32>().unwrap_or(0);
            bt_items.push(format!(
                "{{\"name\":{},\"index\":{},\"status\":\"detected\"}}",
                json_str(&n),
                idx
            ));
        }
    }

    let mut serial_items: Vec<String> = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/dev/serial/by-id") {
        let mut names: Vec<String> = entries
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        names.sort();
        for n in names.into_iter().take(12) {
            let full = format!("/dev/serial/by-id/{}", n);
            serial_items.push(format!(
                "{{\"name\":{},\"path\":{}}}",
                json_str(&n),
                json_str(&full)
            ));
        }
    }

    let probe = |addr: &str| -> bool {
        addr.parse::<std::net::SocketAddr>()
            .ok()
            .map(|sa| std::net::TcpStream::connect_timeout(&sa, std::time::Duration::from_millis(180)).is_ok())
            .unwrap_or(false)
    };
    let svc_items = [
        ("python-matter-server", "127.0.0.1:5580"),
        ("otbr-agent REST (:8081)", "127.0.0.1:8081"),
        ("otbr-agent REST (:5581)", "127.0.0.1:5581"),
    ]
    .iter()
    .map(|(name, ep)| {
        format!(
            "{{\"name\":{},\"endpoint\":{},\"reachable\":{}}}",
            json_str(name),
            json_str(ep),
            probe(ep)
        )
    })
    .collect::<Vec<_>>()
    .join(",");

    format!(
        "{{\"demo\":false,\"matter_bluetooth_enabled\":{},\"bluetooth_adapters\":[{}],\"serial_devices\":[{}],\"local_services\":[{}]}}",
        matter_bluetooth_enabled,
        bt_items.join(","),
        serial_items.join(","),
        svc_items
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_real_otbr_node_and_dataset_masks_secrets() {
        let node_json = r#"{
            "state": "leader",
            "routerCount": 2,
            "rlocAddress": "fd00:db8::ff:fe00:6c00",
            "extAddress": "02000000000000AA",
            "networkName": "Demo-OTBR",
            "rloc16": "0x6c00",
            "leaderData": { "partitionId": 123456, "weighting": 65 },
            "extPanId": "deadbeef11223344"
        }"#;
        let ds_json = r#"{
            "networkKey": "00112233445566778899aabbccddeeff",
            "pskc": "ffeeddccbbaa99887766554433221100",
            "meshLocalPrefix": "fd00:db8::/64",
            "panId": 43981,
            "channel": 25
        }"#;
        let mut br = BorderRouterInfo::default();
        parse_otbr_node_json(node_json, &mut br);
        parse_otbr_dataset_json(ds_json, &mut br);

        assert_eq!(br.state, "leader");
        assert_eq!(br.channel, 25);
        assert_eq!(br.pan_id, "0xabcd");
        assert_eq!(br.partition_id, 123456);
        assert_eq!(br.ext_address, "02000000000000aa");
        // Zero-Trust: raw key material must NEVER appear unmasked
        assert_eq!(br.network_key_masked, "****...eeff");
        assert_eq!(br.pskc_masked, "****...1100");
        assert!(!br.network_key_masked.contains("00112233"));
    }

    #[test]
    fn test_parse_otctl_router_child_and_neighbor_tables() {
        let router_tbl = "\
| ID | RLOC16 | Next Hop | Path Cost | LQ In | LQ Out | Age | Extended MAC     | Link |
+----+--------+----------+-----------+-------+--------+-----+------------------+------+
| 27 | 0x6c00 |       63 |         0 |     0 |      0 |   0 | 0200000000000001 |    0 |
Done
";
        let child_tbl = "\
| ID  | RLOC16 | Timeout    | Age        | LQ In | C_VN |R|D|N|Ver|CSL|QMsgCnt|Suprvsn| Extended MAC     |
+-----+--------+------------+------------+-------+------+-+-+-+---+---+-------+-------+------------------+
|   2 | 0x6c02 |        240 |         11 |     3 |  234 |0|0|0|  4| 0 |     1 |   129 | 0200000000000002 |
|   1 | 0x6c01 |        240 |         10 |     2 |  234 |1|0|0|  4| 0 |     0 |   129 | 0200000000000003 |
Done
";
        let neighbor_tbl = "\
| Role | RLOC16 | Age | Avg RSSI | Last RSSI | LQ In |R|D|N| Extended MAC     | Version |
+------+--------+-----+----------+-----------+-------+-+-+-+------------------+---------+
|   C  | 0x6c02 |  11 |      -62 |       -61 |     3 |0|0|0| 0200000000000002 |       4 |
|   C  | 0x6c01 |  10 |      -83 |       -85 |     2 |1|0|0| 0200000000000003 |       4 |
Done
";
        let mut nodes = parse_otctl_router_table(router_tbl, "0x6c00");
        nodes.extend(parse_otctl_child_table(child_tbl, "0x6c00"));
        apply_otctl_neighbor_table(neighbor_tbl, &mut nodes, "0x6c00");

        assert_eq!(nodes.len(), 3);
        assert_eq!(nodes[0].role, ThreadRole::Leader);
        assert_eq!(nodes[1].role, ThreadRole::Sed);
        assert!(nodes[1].is_sleepy);
        assert_eq!(nodes[1].avg_rssi_dbm, -62);
        assert_eq!(nodes[1].signal_quality(), "excellent");
        assert_eq!(nodes[2].role, ThreadRole::Child);
        assert!(!nodes[2].is_sleepy);
        assert_eq!(nodes[2].avg_rssi_dbm, -83);
        assert_eq!(nodes[2].signal_quality(), "fair");
    }

    #[test]
    fn test_matter_l7_correlation_onto_thread_node() {
        let mut snap = build_demo_snapshot();
        let target_ext = "0200000000000004".to_string();
        correlate_matter_nodes(
            &mut snap.nodes,
            &[MatterDeviceSummary {
                node_id: 99,
                ext_address: target_ext.clone(),
                vendor: "TestVendor".to_string(),
                product: "Matter Sensor Pro".to_string(),
                state_summary: "22.0°C".to_string(),
                clusters: vec!["TemperatureMeasurement".to_string()],
            }],
        );
        let found = snap.nodes.iter().find(|n| n.ext_address == target_ext).unwrap();
        assert_eq!(found.matter_node_id, Some(99));
        assert_eq!(found.matter_product.as_deref(), Some("Matter Sensor Pro"));
    }

    #[test]
    fn test_mqtt_packet_encoding_and_zero_secret_redaction() {
        assert_eq!(encode_mqtt_remaining_length(0), vec![0x00]);
        assert_eq!(encode_mqtt_remaining_length(127), vec![0x7f]);
        assert_eq!(encode_mqtt_remaining_length(128), vec![0x80, 0x01]);
        assert_eq!(encode_mqtt_remaining_length(16384), vec![0x80, 0x80, 0x01]);

        let conn = encode_mqtt_connect(
            "t2m-test",
            Some("user"),
            Some("pass"),
            Some("thread2mqtt/bridge/state"),
            Some("offline"),
            60,
        );
        assert_eq!(conn[0], 0x10);

        let leaky = r#"{"channel":25,"networkKey":"0011223344556677","pskc":"aabbccdd"}"#;
        let pub_pkt = encode_mqtt_publish("thread2mqtt/bridge/info", leaky, true);
        assert_eq!(pub_pkt[0], 0x31); // PUBLISH + RETAIN
        let as_txt = String::from_utf8_lossy(&pub_pkt);
        assert!(!as_txt.contains("0011223344556677"));
        assert!(!as_txt.contains("aabbccdd"));
        assert!(as_txt.contains("REDACTED"));
    }

    #[test]
    fn test_ha_mqtt_auto_discovery_structure() {
        let snap = build_demo_snapshot();
        let payloads = build_ha_discovery_payloads("homeassistant", "thread2mqtt", &snap);
        // 2 bridge entities + 3 diagnostic entities * 6 demo nodes = 20
        assert_eq!(payloads.len(), 20);
        assert!(payloads.iter().any(|(t, p)| t == "homeassistant/binary_sensor/thread2mqtt_bridge_state/config" && p.contains("connectivity")));
        assert!(payloads.iter().any(|(t, p)| t.ends_with("_rssi/config") && p.contains("signal_strength") && p.contains("via_device")));
        for (_, p) in &payloads {
            assert!(!p.contains("networkKey"));
        }
    }

    #[test]
    fn test_prometheus_metrics_and_friendly_name_sanitization() {
        let snap = build_demo_snapshot();
        let prom = render_prometheus_metrics(&snap);
        assert!(prom.contains("thread2mqtt_up 1"));
        assert!(prom.contains("thread2mqtt_channel 25"));
        assert!(prom.contains("thread2mqtt_mesh_nodes_total 6"));
        assert!(prom.contains("thread2mqtt_node_rssi_dbm{"));
        assert!(prom.contains("thread2mqtt_node_lqi_in{"));

        assert_eq!(
            sanitize_friendly_name("  <script>Office Sensor\"  \n"),
            Some("scriptOffice Sensor".to_string())
        );
        assert_eq!(sanitize_friendly_name("   \n\t "), None);
    }

    #[test]
    fn test_scan_local_hardware_demo_json() {
        let j = scan_local_hardware(true, true);
        assert!(j.contains("\"demo\":true"));
        assert!(j.contains("\"matter_bluetooth_enabled\":true"));
        assert!(j.contains("\"hci0\""));
        assert!(j.contains("python-matter-server"));

        let snap = build_demo_snapshot();
        assert!(snap.matter_bluetooth_enabled);
        assert!(snap.to_json().contains("\"matter_bluetooth_enabled\":true"));
    }
}
