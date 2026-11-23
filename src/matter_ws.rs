//! Minimal Pure-Rust `std` RFC 6455 WebSocket Client & RFC 8259 JSON Parser
//! for live `python-matter-server` L7 correlation (0 external crates).
//!
//! Fetches real Matter nodes (Vendor, Product, Firmware SW/HW, Serial, Battery,
//! Fabrics, Exposes/Clusters) and supports Ping & Identify diagnostics.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

// ============================================================================
// 1. Minimal RFC 8259 JSON Value Parser (~130 lines, pure std)
// ============================================================================

#[derive(Clone, Debug, PartialEq)]
pub enum JsonVal {
    Null,
    Bool(bool),
    Int(i64),
    Uint(u64),
    Num(f64),
    Str(String),
    Arr(Vec<JsonVal>),
    Obj(BTreeMap<String, JsonVal>),
}

impl JsonVal {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            JsonVal::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            JsonVal::Num(n) => Some(*n),
            JsonVal::Int(n) => Some(*n as f64),
            JsonVal::Uint(n) => Some(*n as f64),
            _ => None,
        }
    }
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            JsonVal::Int(n) => Some(*n),
            JsonVal::Uint(n) => i64::try_from(*n).ok(),
            JsonVal::Num(n) => Some(*n as i64),
            _ => None,
        }
    }
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            JsonVal::Uint(n) => Some(*n),
            JsonVal::Int(n) if *n >= 0 => Some(*n as u64),
            JsonVal::Num(n) if *n >= 0.0 => Some(*n as u64),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            JsonVal::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn as_arr(&self) -> Option<&[JsonVal]> {
        match self {
            JsonVal::Arr(a) => Some(a.as_slice()),
            _ => None,
        }
    }
    pub fn as_obj(&self) -> Option<&BTreeMap<String, JsonVal>> {
        match self {
            JsonVal::Obj(o) => Some(o),
            _ => None,
        }
    }
    pub fn get(&self, key: &str) -> Option<&JsonVal> {
        self.as_obj().and_then(|o| o.get(key))
    }
}

struct JsonParser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> JsonParser<'a> {
    fn skip_ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\n' | b'\r' | b'\t') {
            self.i += 1;
        }
    }
    fn parse_val(&mut self, depth: usize) -> Option<JsonVal> {
        if depth > 48 {
            return None;
        }
        self.skip_ws();
        if self.i >= self.b.len() {
            return None;
        }
        match self.b[self.i] {
            b'"' => self.parse_str().map(JsonVal::Str),
            b'{' => self.parse_obj(depth + 1),
            b'[' => self.parse_arr(depth + 1),
            b't' if self.b[self.i..].starts_with(b"true") => {
                self.i += 4;
                Some(JsonVal::Bool(true))
            }
            b'f' if self.b[self.i..].starts_with(b"false") => {
                self.i += 5;
                Some(JsonVal::Bool(false))
            }
            b'n' if self.b[self.i..].starts_with(b"null") => {
                self.i += 4;
                Some(JsonVal::Null)
            }
            b'-' | b'0'..=b'9' => self.parse_num(),
            _ => None,
        }
    }
    fn parse_str(&mut self) -> Option<String> {
        if self.b.get(self.i) != Some(&b'"') {
            return None;
        }
        self.i += 1;
        let mut out = String::new();
        while self.i < self.b.len() {
            let c = self.b[self.i];
            self.i += 1;
            if c == b'"' {
                return Some(out);
            }
            if c == b'\\' && self.i < self.b.len() {
                let esc = self.b[self.i];
                self.i += 1;
                match esc {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'u' if self.i + 4 <= self.b.len() => {
                        if let Ok(hex) = std::str::from_utf8(&self.b[self.i..self.i + 4]) {
                            if let Ok(code) = u32::from_str_radix(hex, 16) {
                                if let Some(ch) = char::from_u32(code) {
                                    out.push(ch);
                                }
                            }
                        }
                        self.i += 4;
                    }
                    other => out.push(other as char),
                }
            } else if c < 0x80 {
                out.push(c as char);
            } else {
                // Multi-byte UTF-8 sequence
                let start = self.i - 1;
                while self.i < self.b.len() && (self.b[self.i] & 0xC0) == 0x80 {
                    self.i += 1;
                }
                if let Ok(s) = std::str::from_utf8(&self.b[start..self.i]) {
                    out.push_str(s);
                }
            }
        }
        None
    }
    fn parse_num(&mut self) -> Option<JsonVal> {
        let start = self.i;
        while self.i < self.b.len()
            && matches!(self.b[self.i], b'-' | b'+' | b'0'..=b'9' | b'.' | b'e' | b'E')
        {
            self.i += 1;
        }
        let s = std::str::from_utf8(&self.b[start..self.i]).ok()?;
        // Preserve full 64-bit integer precision (e.g. compressed_fabric_id, Matter Node IDs)
        if !s.contains('.') && !s.contains('e') && !s.contains('E') {
            if !s.starts_with('-') {
                if let Ok(u) = s.parse::<u64>() {
                    return Some(JsonVal::Uint(u));
                }
            }
            if let Ok(i) = s.parse::<i64>() {
                return Some(JsonVal::Int(i));
            }
        }
        s.parse::<f64>().ok().map(JsonVal::Num)
    }
    fn parse_arr(&mut self, depth: usize) -> Option<JsonVal> {
        self.i += 1; // '['
        let mut items = Vec::new();
        loop {
            self.skip_ws();
            if self.b.get(self.i) == Some(&b']') {
                self.i += 1;
                return Some(JsonVal::Arr(items));
            }
            items.push(self.parse_val(depth)?);
            self.skip_ws();
            match self.b.get(self.i) {
                Some(&b',') => self.i += 1,
                Some(&b']') => {
                    self.i += 1;
                    return Some(JsonVal::Arr(items));
                }
                _ => return None,
            }
        }
    }
    fn parse_obj(&mut self, depth: usize) -> Option<JsonVal> {
        self.i += 1; // '{'
        let mut map = BTreeMap::new();
        loop {
            self.skip_ws();
            if self.b.get(self.i) == Some(&b'}') {
                self.i += 1;
                return Some(JsonVal::Obj(map));
            }
            let key = self.parse_str()?;
            self.skip_ws();
            if self.b.get(self.i) != Some(&b':') {
                return None;
            }
            self.i += 1;
            let val = self.parse_val(depth)?;
            map.insert(key, val);
            self.skip_ws();
            match self.b.get(self.i) {
                Some(&b',') => self.i += 1,
                Some(&b'}') => {
                    self.i += 1;
                    return Some(JsonVal::Obj(map));
                }
                _ => return None,
            }
        }
    }
}

pub fn parse_json(raw: &str) -> Option<JsonVal> {
    let mut p = JsonParser {
        b: raw.as_bytes(),
        i: 0,
    };
    p.parse_val(0)
}

// ============================================================================
// 2. Matter Server Live Data Models
// ============================================================================

#[derive(Clone, Debug)]
pub struct MatterExpose {
    pub name: String,
    pub property: String,
    pub value: String,
    pub unit: String,
    pub cluster: String,
    pub access: String,
}

#[derive(Clone, Debug)]
pub struct MatterFabricInfo {
    pub fabric_index: u32,
    pub vendor_id: u32,
    pub label: String,
    pub node_id: u64,
}

#[derive(Clone, Debug)]
pub struct LiveMatterNode {
    pub node_id: u64,
    pub available: bool,
    pub vendor: String,
    pub product: String,
    pub node_label: String,
    pub sw_version: String,
    pub hw_version: String,
    pub serial: String,
    pub battery_pct: Option<u8>,
    pub battery_mv: Option<u32>,
    pub battery_type: Option<String>,
    pub state_summary: String,
    pub clusters: Vec<String>,
    pub exposes: Vec<MatterExpose>,
    pub fabrics: Vec<MatterFabricInfo>,
}

#[derive(Clone, Debug, Default)]
pub struct MatterServerSnapshot {
    pub connected: bool,
    pub endpoint: String,
    pub sdk_version: String,
    pub compressed_fabric_id: String,
    pub bluetooth_enabled: bool,
    pub nodes: Vec<LiveMatterNode>,
}

// ============================================================================
// 3. RFC 6455 Pure-Std WebSocket Wire Transport
// ============================================================================

fn parse_ws_url(url: &str) -> Result<(String, String), String> {
    let rest = url
        .trim()
        .strip_prefix("ws://")
        .or_else(|| url.trim().strip_prefix("http://"))
        .ok_or_else(|| "MATTER_WS_URL must start with ws:// or http://".to_string())?;
    let (host_port, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/ws"),
    };
    let hp = if host_port.contains(':') {
        host_port.to_string()
    } else {
        format!("{}:5580", host_port)
    };
    Ok((hp, path.to_string()))
}

fn ws_connect(url: &str, timeout_ms: u64) -> Result<TcpStream, String> {
    let (host_port, path) = parse_ws_url(url)?;
    let mut stream = TcpStream::connect(&host_port)
        .map_err(|e| format!("Matter WS connect {} KO: {}", host_port, e))?;
    let dur = Some(Duration::from_millis(timeout_ms));
    let _ = stream.set_read_timeout(dur);
    let _ = stream.set_write_timeout(dur);

    // RFC 6455 §4.1: Sec-WebSocket-Key MUST be base64 of exactly 16 bytes (24 chars)
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhyZWFkMm1xdHRrZXkxNg==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        path, host_port
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("Matter WS handshake write KO: {}", e))?;

    // Read HTTP 101 response header byte-by-byte until \r\n\r\n (never over-read WS frame bytes)
    let mut hdr = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    while hdr.len() < 8192 {
        stream
            .read_exact(&mut byte)
            .map_err(|e| format!("Matter WS handshake read KO: {}", e))?;
        hdr.push(byte[0]);
        if hdr.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let hdr_str = String::from_utf8_lossy(&hdr);
    if !hdr_str.contains("101") {
        return Err(format!(
            "Matter WS upgrade rejected: {}",
            hdr_str.lines().next().unwrap_or("unknown")
        ));
    }
    Ok(stream)
}

fn ws_send_frame(stream: &mut TcpStream, opcode: u8, payload: &[u8]) -> Result<(), String> {
    let mut frame = Vec::with_capacity(payload.len() + 14);
    frame.push(0x80 | (opcode & 0x0f));
    let len = payload.len();
    if len < 126 {
        frame.push(0x80 | (len as u8));
    } else if len <= 65535 {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        frame.push(0x80 | 127);
        frame.extend_from_slice(&(len as u64).to_be_bytes());
    }
    let mask: [u8; 4] = [0x54, 0x32, 0x4D, 0x7A];
    frame.extend_from_slice(&mask);
    for (idx, b) in payload.iter().enumerate() {
        frame.push(b ^ mask[idx & 3]);
    }
    stream
        .write_all(&frame)
        .map_err(|e| format!("Matter WS write KO: {}", e))
}

fn ws_read_text(stream: &mut TcpStream) -> Result<String, String> {
    let mut message = Vec::new();
    let max_bytes: usize = 4 * 1024 * 1024;
    loop {
        let mut h = [0u8; 2];
        stream
            .read_exact(&mut h)
            .map_err(|e| format!("Matter WS frame hdr KO: {}", e))?;
        let fin = (h[0] & 0x80) != 0;
        let opcode = h[0] & 0x0f;
        let masked = (h[1] & 0x80) != 0;
        let mut len = (h[1] & 0x7f) as usize;
        if len == 126 {
            let mut ext = [0u8; 2];
            stream.read_exact(&mut ext).map_err(|e| format!("WS len16 KO: {}", e))?;
            len = u16::from_be_bytes(ext) as usize;
        } else if len == 127 {
            let mut ext = [0u8; 8];
            stream.read_exact(&mut ext).map_err(|e| format!("WS len64 KO: {}", e))?;
            len = u64::from_be_bytes(ext) as usize;
        }
        if message.len().saturating_add(len) > max_bytes {
            return Err("Matter WS payload exceeds 4 MiB safety cap".to_string());
        }
        let mut mask = [0u8; 4];
        if masked {
            stream.read_exact(&mut mask).map_err(|e| format!("WS mask KO: {}", e))?;
        }
        let mut data = vec![0u8; len];
        if len > 0 {
            stream.read_exact(&mut data).map_err(|e| format!("WS payload KO: {}", e))?;
        }
        if masked {
            for (i, b) in data.iter_mut().enumerate() {
                *b ^= mask[i & 3];
            }
        }
        match opcode {
            0x8 => return Err("Matter WS closed by server".to_string()),
            0x9 => {
                let _ = ws_send_frame(stream, 0xA, &data);
                continue;
            }
            0xA => continue,
            0x1 | 0x0 => {
                message.extend_from_slice(&data);
                if fin {
                    return String::from_utf8(message).map_err(|e| format!("WS UTF-8 KO: {}", e));
                }
            }
            _ => continue,
        }
    }
}

// ============================================================================
// 4. High-Level Matter Server Queries & Attribute Extraction
// ============================================================================

/// Looks up a Matter attribute across endpoint 1 first, then any other endpoint (`<ep>/<cluster>/<attr>`).
fn find_cluster_attr<'a>(attrs: &'a JsonVal, cluster: u32, attr: u32) -> Option<&'a JsonVal> {
    let ep1 = format!("1/{}/{}", cluster, attr);
    if let Some(v) = attrs.get(&ep1) {
        return Some(v);
    }
    let suffix = format!("/{}/{}", cluster, attr);
    if let Some(obj) = attrs.as_obj() {
        for (k, v) in obj {
            if k.ends_with(&suffix) {
                return Some(v);
            }
        }
    }
    None
}

fn extract_matter_node(node_val: &JsonVal) -> Option<LiveMatterNode> {
    let node_id = node_val.get("node_id")?.as_u64()?;
    let available = node_val.get("available").and_then(|v| v.as_bool()).unwrap_or(false);
    let attrs = node_val.get("attributes")?;

    let astr = |k: &str| attrs.get(k).and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let vendor = astr("0/40/1");
    let product = astr("0/40/3");
    let node_label = astr("0/40/5");
    let hw_version = astr("0/40/8");
    let sw_version = astr("0/40/10");
    let serial = astr("0/40/15");

    // Battery (PowerSource Cluster 47 / 0x002F on any endpoint)
    let bat_raw = find_cluster_attr(attrs, 47, 12).and_then(|v| v.as_u64());
    let battery_pct = bat_raw.map(|v| ((v / 2).min(100)) as u8);
    let battery_mv = find_cluster_attr(attrs, 47, 11)
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);
    let battery_type = find_cluster_attr(attrs, 47, 19)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let mut clusters = Vec::new();
    let mut exposes = Vec::new();
    let mut state_parts = Vec::new();

    if let Some(pct) = battery_pct {
        clusters.push("PowerSource".to_string());
        exposes.push(MatterExpose {
            name: "Battery".to_string(),
            property: "battery".to_string(),
            value: format!("{}", pct),
            unit: "%".to_string(),
            cluster: "0x002F PowerSource".to_string(),
            access: "R".to_string(),
        });
        state_parts.push(format!("Bat {}%", pct));
    }
    if let Some(mv) = battery_mv {
        exposes.push(MatterExpose {
            name: "Voltage".to_string(),
            property: "voltage".to_string(),
            value: format!("{:.2}", (mv as f64) / 1000.0),
            unit: "V".to_string(),
            cluster: "0x002F PowerSource".to_string(),
            access: "R".to_string(),
        });
    }
    // Smoke / CO Alarm (Cluster 92 / 0x005C)
    if let Some(smoke) = find_cluster_attr(attrs, 92, 1).and_then(|v| v.as_i64()) {
        clusters.push("SmokeCoAlarm".to_string());
        let label = match smoke {
            0 => "Clear",
            1 => "Warning",
            2 => "CRITICAL ALARM",
            _ => "Unknown",
        };
        exposes.push(MatterExpose {
            name: "Smoke State".to_string(),
            property: "smoke_state".to_string(),
            value: label.to_string(),
            unit: String::new(),
            cluster: "0x005C SmokeCoAlarm".to_string(),
            access: "R".to_string(),
        });
        let test_in_prog = find_cluster_attr(attrs, 92, 5).and_then(|v| v.as_bool()).unwrap_or(false);
        exposes.push(MatterExpose {
            name: "Self-Test Active".to_string(),
            property: "test_in_progress".to_string(),
            value: if test_in_prog { "Yes" } else { "No" }.to_string(),
            unit: String::new(),
            cluster: "0x005C SmokeCoAlarm".to_string(),
            access: "R".to_string(),
        });
        state_parts.insert(0, format!("Smoke: {}", label));
    }
    // OnOff (Cluster 6 / 0x0006)
    if let Some(onoff) = find_cluster_attr(attrs, 6, 0).and_then(|v| v.as_bool()) {
        clusters.push("OnOff".to_string());
        let st = if onoff { "ON" } else { "OFF" };
        exposes.push(MatterExpose {
            name: "Switch State".to_string(),
            property: "state".to_string(),
            value: st.to_string(),
            unit: String::new(),
            cluster: "0x0006 OnOff".to_string(),
            access: "RW".to_string(),
        });
        state_parts.insert(0, st.to_string());
    }
    // LevelControl (Cluster 8 / 0x0008)
    if let Some(lvl) = find_cluster_attr(attrs, 8, 0).and_then(|v| v.as_u64()) {
        clusters.push("LevelControl".to_string());
        let pct = ((lvl * 100) / 254).min(100);
        exposes.push(MatterExpose {
            name: "Brightness / Level".to_string(),
            property: "brightness".to_string(),
            value: format!("{}", pct),
            unit: "%".to_string(),
            cluster: "0x0008 LevelControl".to_string(),
            access: "RW".to_string(),
        });
    }
    // Temperature (Cluster 1026 / 0x0402)
    if let Some(temp) = find_cluster_attr(attrs, 1026, 0).and_then(|v| v.as_i64()) {
        clusters.push("TemperatureMeasurement".to_string());
        let deg = (temp as f64) / 100.0;
        exposes.push(MatterExpose {
            name: "Temperature".to_string(),
            property: "temperature".to_string(),
            value: format!("{:.1}", deg),
            unit: "°C".to_string(),
            cluster: "0x0402 Temperature".to_string(),
            access: "R".to_string(),
        });
        state_parts.insert(0, format!("{:.1}°C", deg));
    }
    // Humidity (Cluster 1029 / 0x0405)
    if let Some(hum) = find_cluster_attr(attrs, 1029, 0).and_then(|v| v.as_i64()) {
        clusters.push("RelativeHumidity".to_string());
        let pct = (hum as f64) / 100.0;
        exposes.push(MatterExpose {
            name: "Humidity".to_string(),
            property: "humidity".to_string(),
            value: format!("{:.0}", pct),
            unit: "%".to_string(),
            cluster: "0x0405 Humidity".to_string(),
            access: "R".to_string(),
        });
        state_parts.push(format!("{:.0}% RH", pct));
    }
    // Contact / BooleanState (Cluster 69 / 0x0045)
    if let Some(contact) = find_cluster_attr(attrs, 69, 0).and_then(|v| v.as_bool()) {
        clusters.push("BooleanState".to_string());
        let st = if contact { "Closed" } else { "Open" };
        exposes.push(MatterExpose {
            name: "Contact".to_string(),
            property: "contact".to_string(),
            value: st.to_string(),
            unit: String::new(),
            cluster: "0x0045 BooleanState".to_string(),
            access: "R".to_string(),
        });
        state_parts.insert(0, st.to_string());
    }
    // Occupancy (Cluster 1030 / 0x0406)
    if let Some(occ) = find_cluster_attr(attrs, 1030, 0).and_then(|v| v.as_u64()) {
        clusters.push("OccupancySensing".to_string());
        let st = if (occ & 1) != 0 { "Occupied" } else { "Clear" };
        exposes.push(MatterExpose {
            name: "Occupancy".to_string(),
            property: "occupancy".to_string(),
            value: st.to_string(),
            unit: String::new(),
            cluster: "0x0406 Occupancy".to_string(),
            access: "R".to_string(),
        });
        state_parts.insert(0, st.to_string());
    }
    if attrs.get("0/53/0").is_some() {
        clusters.push("ThreadNetworkDiagnostics".to_string());
    }
    if find_cluster_attr(attrs, 3, 0).is_some() {
        clusters.push("Identify".to_string());
    }

    // Operational Credentials Fabrics (0/62/1) — CSA DCL official Vendor IDs
    let mut fabrics = Vec::new();
    if let Some(arr) = attrs.get("0/62/1").and_then(|v| v.as_arr()) {
        for f in arr {
            let vendor_id = f.get("2").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let fabric_index = f.get("254").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let f_node_id = f.get("4").and_then(|v| v.as_u64()).unwrap_or(node_id);
            let label = f
                .get("5")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .unwrap_or(match vendor_id {
                    4939 => "Home Assistant",
                    4937 => "Apple Home",
                    4996 => "Apple Keychain",
                    24582 => "Google Home",
                    4631 => "Amazon Alexa",
                    4362 => "Samsung SmartThings",
                    _ => "Matter Controller",
                })
                .to_string();
            fabrics.push(MatterFabricInfo {
                fabric_index,
                vendor_id,
                label,
                node_id: f_node_id,
            });
        }
    }

    let state_summary = if state_parts.is_empty() {
        if available { "Online".to_string() } else { "Offline".to_string() }
    } else {
        state_parts.join(" · ")
    };

    Some(LiveMatterNode {
        node_id,
        available,
        vendor: if vendor.is_empty() { "Matter Vendor".to_string() } else { vendor },
        product: if product.is_empty() { format!("Matter Node #{}", node_id) } else { product },
        node_label,
        sw_version,
        hw_version,
        serial,
        battery_pct,
        battery_mv,
        battery_type,
        state_summary,
        clusters,
        exposes,
        fabrics,
    })
}

/// Connects to `python-matter-server` WebSocket and fetches all live Matter nodes & attributes.
pub fn fetch_matter_server_snapshot(ws_url: &str, timeout_ms: u64) -> Result<MatterServerSnapshot, String> {
    let mut stream = ws_connect(ws_url, timeout_ms)?;
    let info_raw = ws_read_text(&mut stream)?;
    let info_val = parse_json(&info_raw).ok_or_else(|| "Invalid Matter server_info JSON".to_string())?;

    let sdk_version = info_val
        .get("sdk_version")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let compressed_fabric_id = info_val
        .get("compressed_fabric_id")
        .and_then(|v| v.as_u64())
        .map(|n| format!("{:016X}", n))
        .unwrap_or_default();
    let bluetooth_enabled = info_val
        .get("bluetooth_enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let req = r#"{"message_id":"t2m-nodes","command":"get_nodes"}"#;
    ws_send_frame(&mut stream, 0x1, req.as_bytes())?;

    let mut nodes = Vec::new();
    for _ in 0..8 {
        let resp_raw = ws_read_text(&mut stream)?;
        if let Some(val) = parse_json(&resp_raw) {
            if val.get("message_id").and_then(|v| v.as_str()) == Some("t2m-nodes") {
                if let Some(arr) = val.get("result").and_then(|v| v.as_arr()) {
                    for nv in arr {
                        if let Some(node) = extract_matter_node(nv) {
                            nodes.push(node);
                        }
                    }
                }
                break;
            }
        }
    }
    let _ = ws_send_frame(&mut stream, 0x8, &[]);

    Ok(MatterServerSnapshot {
        connected: true,
        endpoint: ws_url.to_string(),
        sdk_version,
        compressed_fabric_id,
        bluetooth_enabled,
        nodes,
    })
}

/// Shared pure-Rust RFC 6455 helper sending one command to `python-matter-server` and returning its matching reply.
fn matter_ws_command(ws_url: &str, msg_id: &str, command: &str, args_json: Option<&str>, timeout_ms: u64) -> Result<String, String> {
    let mut stream = ws_connect(ws_url, timeout_ms)?;
    let _ = ws_read_text(&mut stream)?; // consume server_info
    let req = match args_json {
        Some(args) => format!(
            r#"{{"message_id":"{}","command":"{}","args":{}}}"#,
            msg_id, command, args
        ),
        None => format!(r#"{{"message_id":"{}","command":"{}"}}"#, msg_id, command),
    };
    ws_send_frame(&mut stream, 0x1, req.as_bytes())?;
    for _ in 0..24 {
        let resp = ws_read_text(&mut stream)?;
        let matched = parse_json(&resp)
            .and_then(|v| v.get("message_id").and_then(|m| m.as_str()).map(|s| s == msg_id))
            .unwrap_or(false);
        if matched {
            let _ = ws_send_frame(&mut stream, 0x8, &[]);
            return Ok(resp);
        }
    }
    Err(format!("Matter {} timeout", command))
}

/// Sends a read-only `ping_node` diagnostic to `python-matter-server` and returns IP reachability JSON.
pub fn matter_ping_node(ws_url: &str, node_id: u64, timeout_ms: u64) -> Result<String, String> {
    matter_ws_command(
        ws_url,
        "t2m-ping",
        "ping_node",
        Some(&format!(r#"{{"node_id":{},"attempts":1}}"#, node_id)),
        timeout_ms,
    )
}

/// Read-only mDNS discovery of nearby commissionable Matter/Thread nodes.
pub fn matter_discover_commissionable(ws_url: &str, timeout_ms: u64) -> Result<String, String> {
    matter_ws_command(ws_url, "t2m-disc", "discover", None, timeout_ms)
}

/// Read-only CSA DCL firmware OTA update check for a commissioned Matter node.
pub fn matter_check_node_update(ws_url: &str, node_id: u64, timeout_ms: u64) -> Result<String, String> {
    matter_ws_command(
        ws_url,
        "t2m-ota",
        "check_node_update",
        Some(&format!(r#"{{"node_id":{}}}"#, node_id)),
        timeout_ms,
    )
}

/// Commissions (joins) a new Matter-over-Thread device using a QR payload (`MT:...`) or 11/21-digit manual code.
pub fn matter_commission_with_code(ws_url: &str, code: &str, network_only: bool, timeout_ms: u64) -> Result<String, String> {
    let clean: String = code
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '.' | '-' | '+' | '$'))
        .collect();
    if clean.is_empty() {
        return Err("Empty Matter setup code".to_string());
    }
    let args = format!(
        r#"{{"code":"{}","network_only":{}}}"#,
        clean,
        if network_only { "true" } else { "false" }
    );
    matter_ws_command(ws_url, "t2m-comm", "commission_with_code", Some(&args), timeout_ms)
}

/// Opens an Enhanced Commissioning Window (Multi-Admin ECW) on an existing Matter node and returns live QR/Manual code.
pub fn matter_open_commissioning_window(ws_url: &str, node_id: u64, timeout_secs: u32, timeout_ms: u64) -> Result<String, String> {
    let t = timeout_secs.clamp(180, 900);
    matter_ws_command(
        ws_url,
        "t2m-ecw",
        "open_commissioning_window",
        Some(&format!(r#"{{"node_id":{},"timeout":{}}}"#, node_id, t)),
        timeout_ms,
    )
}

/// Triggers a live Matter node re-interview (refreshes clusters, firmware, and attributes).
pub fn matter_interview_node(ws_url: &str, node_id: u64, timeout_ms: u64) -> Result<String, String> {
    matter_ws_command(
        ws_url,
        "t2m-intv",
        "interview_node",
        Some(&format!(r#"{{"node_id":{}}}"#, node_id)),
        timeout_ms,
    )
}

/// Triggers Matter Identify cluster (0x0003) command `"Identify"` so a physical device blinks/beeps.
pub fn matter_identify_node(
    ws_url: &str,
    node_id: u64,
    endpoint_id: u16,
    identify_time_s: u16,
    timeout_ms: u64,
) -> Result<String, String> {
    let t = identify_time_s.clamp(1, 30);
    let args = format!(
        r#"{{"node_id":{},"endpoint_id":{},"cluster_id":3,"command_name":"Identify","payload":{{"identifyTime":{}}}}}"#,
        node_id, endpoint_id, t
    );
    matter_ws_command(ws_url, "t2m-ident", "device_command", Some(&args), timeout_ms)
}

/// Sends a whitelisted Matter OnOff cluster (0x0006) command (`On` | `Off` | `Toggle`).
pub fn matter_set_onoff(
    ws_url: &str,
    node_id: u64,
    endpoint_id: u16,
    action: &str,
    timeout_ms: u64,
) -> Result<String, String> {
    let cmd = match action.trim().to_ascii_lowercase().as_str() {
        "on" => "On",
        "off" => "Off",
        "toggle" => "Toggle",
        _ => return Err("Invalid OnOff action (expected on|off|toggle)".to_string()),
    };
    let args = format!(
        r#"{{"node_id":{},"endpoint_id":{},"cluster_id":6,"command_name":"{}","payload":{{}}}}"#,
        node_id, endpoint_id, cmd
    );
    matter_ws_command(ws_url, "t2m-onoff", "device_command", Some(&args), timeout_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_parser_and_matter_node_extraction() {
        let sample = r#"{
            "node_id": 7,
            "available": true,
            "attributes": {
                "0/40/1": "ACME-IoT",
                "0/40/3": "Smoke sensor",
                "0/40/8": "1.0",
                "0/40/10": "2.0",
                "0/40/15": "SN-DEMO-001",
                "0/53/0": 25,
                "1/47/11": 3000,
                "1/47/12": 190,
                "1/47/19": "CR123A",
                "1/92/1": 0,
                "1/92/5": false,
                "0/62/1": [{"2": 4939, "4": 7, "5": "", "254": 1}]
            }
        }"#;
        let val = parse_json(sample).expect("parse ok");
        let node = extract_matter_node(&val).expect("node ok");
        assert_eq!(node.node_id, 7);
        assert_eq!(node.vendor, "ACME-IoT");
        assert_eq!(node.battery_pct, Some(95));
        assert_eq!(node.battery_mv, Some(3000));
        assert_eq!(node.battery_type.as_deref(), Some("CR123A"));
        assert!(node.state_summary.contains("Smoke: Clear"));
        assert_eq!(node.fabrics.len(), 1);
        assert_eq!(node.fabrics[0].label, "Home Assistant");

        // Exact 64-bit integer precision (> 2^53) — synthetic RFC-safe vector prevents f64 truncation
        let srv = parse_json(r#"{"compressed_fabric_id": 1311768467463790321}"#).expect("srv ok");
        let cfid = srv.get("compressed_fabric_id").and_then(|v| v.as_u64()).expect("u64 ok");
        assert_eq!(format!("{:016X}", cfid), "123456789ABCDEF1");

        // Multi-endpoint attribute extraction (e.g. temperature on endpoint 2)
        let multi = parse_json(r#"{"node_id": 9, "available": true, "attributes": {"0/40/1": "ACME", "2/1026/0": 2150}}"#).expect("multi ok");
        let mnode = extract_matter_node(&multi).expect("mnode ok");
        assert!(mnode.state_summary.contains("21.5°C"));
    }
}
