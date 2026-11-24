//! Thread2MQTT v0.5 Daemon — Single static pure-Rust `std` binary serving:
//!  - Embedded Web UI (`/` — zero external CDN, HA Ingress ready)
//!  - Live OpenThread Border Router (REST + `ot-ctl`) + Live `python-matter-server` WebSocket correlation
//!  - Automatic SRP (`_matter._tcp`) L2/L3 <-> L7 binding + MAC/IPv6 RF Diagnostics + Health Advisor
//!  - Matter QR/Manual Setup Code Decoder (Base38 + Verhoeff) + Opt-In Commissioning / ECW / OTA / mDNS
//!  - Declarative `configuration.yaml` (fail-closed `read_only_mode: true`) + Persistent `state.json`
//!  - MQTT 3.1.1 Home Assistant Auto-Discovery + Live SSE Logs (`/api/events`) + Prometheus (`/metrics`)

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use thread2mqtt::config::AppConfig;
use thread2mqtt::diagnostics::{
    analyze_mesh_health, check_ipv6_omr_route, compute_node_health_score, decode_matter_setup_code,
    is_whitelisted_otctl, load_node_meta_store, parse_otctl_energy_scan, parse_otctl_ip_counters,
    parse_otctl_mac_counters, parse_otctl_srp_services, save_node_meta_store, IpCounters,
    MacCounters, NodeMeta,
};
use thread2mqtt::matter_ws::{
    fetch_matter_server_snapshot, ha_rename_matter_device, matter_check_node_update,
    matter_commission_with_code, matter_discover_commissionable, matter_identify_node,
    matter_interview_node, matter_open_commissioning_window, matter_ping_node,
    matter_set_node_label, matter_set_onoff, parse_json,
};
use thread2mqtt::{
    apply_otctl_neighbor_table, build_demo_snapshot, build_ha_discovery_payloads,
    correlate_srp_and_matter, fetch_http_json, json_get_i64, json_get_str, json_str, now_epoch_s,
    parse_otbr_dataset_json, parse_otbr_node_json, parse_otctl_child_table,
    parse_otctl_router_table, rebuild_mesh_links, render_prometheus_metrics,
    sanitize_friendly_name, sanitize_mqtt_payload, sanitize_pairing_code, sanitize_topic_slug,
    scan_local_hardware, BorderRouterInfo, MeshSnapshot, MqttPublisher, ThreadNode, ThreadRole,
};

const EMBEDDED_UI_HTML: &str = include_str!("ui/index.html");
const EMBEDDED_LOGO_PNG: &[u8] = include_bytes!("../assets/logo.png");
const EMBEDDED_DEV_SLZB: &[u8] = include_bytes!("../assets/devices/smlight_slzb_mr4u.webp");
const EMBEDDED_DEV_EVE_ENERGY: &[u8] = include_bytes!("../assets/devices/eve_energy.webp");
const EMBEDDED_DEV_NANOLEAF_A60: &[u8] = include_bytes!("../assets/devices/nanoleaf_essentials_a60.webp");
const EMBEDDED_DEV_AQARA_W100: &[u8] = include_bytes!("../assets/devices/aqara_climate_w100.webp");
const EMBEDDED_DEV_AQARA_P2: &[u8] = include_bytes!("../assets/devices/aqara_door_window_p2.webp");
const EMBEDDED_DEV_HEIMAN_SMOKE: &[u8] = include_bytes!("../assets/devices/heiman_smoke_sensor.webp");

fn builtin_device_image(filename: &str) -> Option<&'static [u8]> {
    match filename.to_ascii_lowercase().as_str() {
        "smlight_slzb_mr4u.webp" | "openthread_border_router_leader.webp" => Some(EMBEDDED_DEV_SLZB),
        "eve_energy.webp" => Some(EMBEDDED_DEV_EVE_ENERGY),
        "nanoleaf_essentials_a60.webp" => Some(EMBEDDED_DEV_NANOLEAF_A60),
        "aqara_climate_w100.webp" => Some(EMBEDDED_DEV_AQARA_W100),
        "aqara_door_window_p2.webp" => Some(EMBEDDED_DEV_AQARA_P2),
        "heiman_smoke_sensor.webp" => Some(EMBEDDED_DEV_HEIMAN_SMOKE),
        _ => None,
    }
}

const MAX_HTTP_THREADS: usize = 28;
const MAX_SSE_CONNS: usize = 8;
const MAX_HEADER_LINE_BYTES: usize = 4096;
const MAX_HEADER_TOTAL_BYTES: usize = 16384;
const MAX_HEADERS_COUNT: usize = 64;
const MAX_NODE_META_ENTRIES: usize = 512;

static ACTIVE_HTTP_THREADS: AtomicUsize = AtomicUsize::new(0);
static ACTIVE_SSE_CONNS: AtomicUsize = AtomicUsize::new(0);

struct SlotGuard(&'static AtomicUsize);

impl SlotGuard {
    fn try_acquire(counter: &'static AtomicUsize, limit: usize) -> Option<Self> {
        loop {
            let cur = counter.load(Ordering::Acquire);
            if cur >= limit {
                return None;
            }
            if counter
                .compare_exchange_weak(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(Self(counter));
            }
        }
    }
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn ct_eq(a: &str, b: &str) -> bool {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    let max_len = ab.len().max(bb.len());
    let mut diff = (ab.len() ^ bb.len()) as u8;
    for i in 0..max_len {
        let x = *ab.get(i).unwrap_or(&0);
        let y = *bb.get(i).unwrap_or(&0);
        diff |= x ^ y;
    }
    diff == 0 && ab.len() == bb.len()
}

fn read_bounded_line<R: BufRead>(reader: &mut R, max_len: usize) -> Result<Option<String>, ()> {
    let mut buf = String::new();
    let n = reader
        .take((max_len + 1) as u64)
        .read_line(&mut buf)
        .map_err(|_| ())?;
    if n == 0 {
        return Ok(None);
    }
    if n > max_len {
        return Err(());
    }
    Ok(Some(buf))
}

fn origin_authority(origin: &str) -> Option<&str> {
    let rest = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))?;
    let auth = rest.split('/').next().unwrap_or("").trim();
    if auth.is_empty() { None } else { Some(auth) }
}

fn sanitize_local_icon(raw: &str) -> Option<String> {
    let s = raw.trim();
    let low = s.to_ascii_lowercase();
    if s.is_empty() || low.contains("://") || low.starts_with("javascript:") || low.starts_with("data:") {
        return None;
    }
    let stripped = s
        .strip_prefix("/device-images/")
        .or_else(|| s.strip_prefix("device-images/"))
        .or_else(|| s.strip_prefix("/device_images/"))
        .or_else(|| s.strip_prefix("device_images/"))
        .unwrap_or(s);
    if stripped.is_empty()
        || stripped.len() > 96
        || stripped.contains("..")
        || stripped.contains('/')
        || stripped.contains('\\')
        || !stripped
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        return None;
    }
    Some(stripped.to_string())
}

fn json_get_bool(raw: &str, key: &str) -> Option<bool> {
    let needle = format!("\"{}\"", key);
    let idx = raw.find(&needle)?;
    let rest = raw[idx + needle.len()..].trim_start().strip_prefix(':')?.trim_start();
    if rest.starts_with("true") {
        Some(true)
    } else if rest.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

fn run_otctl(cmd_prefix: &str, subcmd: &str) -> Result<String, String> {
    let parts: Vec<&str> = cmd_prefix.split_whitespace().collect();
    if parts.is_empty() {
        return Err("empty ot-ctl command".to_string());
    }
    let mut cmd = Command::new(parts[0]);
    for p in &parts[1..] {
        cmd.arg(p);
    }
    for sub in subcmd.split_whitespace() {
        cmd.arg(sub);
    }
    let out = cmd.output().map_err(|e| format!("ot-ctl spawn KO: {}", e))?;
    if !out.status.success() {
        return Err(format!("ot-ctl {} exited {:?}", subcmd, out.status.code()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

fn poll_live_otbr(cfg: &AppConfig, state: &Arc<Mutex<MeshSnapshot>>) {
    let mut br = BorderRouterInfo::default();
    let mut source_parts = Vec::new();
    let mut mac_counters = MacCounters::default();
    let mut ip_counters = IpCounters::default();
    let mut srp_services = Vec::new();
    let mut br_ipaddrs = Vec::new();
    let mut br_omr_prefix = String::new();

    if let Some(url) = &cfg.otbr_url {
        match fetch_http_json(url, "/node", 3000) {
            Ok(body) => {
                parse_otbr_node_json(&body, &mut br);
                source_parts.push(format!("REST {}", url));
            }
            Err(e) => {
                if let Ok(mut s) = state.lock() {
                    s.push_event("WARN", "OTBR", "OTBR REST /node poll failed", &json_str(&e));
                }
            }
        }
        if let Ok(ds) = fetch_http_json(url, "/node/dataset/active", 3000) {
            parse_otbr_dataset_json(&ds, &mut br);
        }
    }

    let mut nodes = Vec::new();
    if let Some(otctl) = &cfg.otctl_cmd {
        source_parts.push("ot-ctl".to_string());
        if let Ok(st) = run_otctl(otctl, "srp server state") {
            br.srp_state = st.lines().next().unwrap_or("unknown").trim().to_string();
        }
        if let Ok(st) = run_otctl(otctl, "br state") {
            br.br_state = st.lines().next().unwrap_or("unknown").trim().to_string();
        }
        if let Ok(rt) = run_otctl(otctl, "router table") {
            nodes.extend(parse_otctl_router_table(&rt, &br.rloc16));
        }
        if let Ok(ct) = run_otctl(otctl, "child table") {
            nodes.extend(parse_otctl_child_table(&ct, &br.rloc16));
        }
        if let Ok(nt) = run_otctl(otctl, "neighbor table") {
            apply_otctl_neighbor_table(&nt, &mut nodes, &br.rloc16);
        }
        if let Ok(mc) = run_otctl(otctl, "counters mac") {
            mac_counters = parse_otctl_mac_counters(&mc);
        }
        if let Ok(ic) = run_otctl(otctl, "counters ip") {
            ip_counters = parse_otctl_ip_counters(&ic);
        }
        if let Ok(srp_raw) = run_otctl(otctl, "srp server service") {
            srp_services = parse_otctl_srp_services(&srp_raw);
        }
        if let Ok(ips) = run_otctl(otctl, "ipaddr") {
            br_ipaddrs = ips
                .lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty() && *l != "Done")
                .map(|l| l.to_string())
                .collect();
        }
        if let Ok(omr) = run_otctl(otctl, "br omrprefix") {
            for line in omr.lines() {
                if let Some(rest) = line.trim().strip_prefix("Favored:") {
                    br_omr_prefix = rest.split_whitespace().next().unwrap_or("").to_string();
                    break;
                }
            }
        }
    }

    if nodes.is_empty() && !br.ext_address.is_empty() {
        nodes.push(ThreadNode {
            rloc16: br.rloc16.clone(),
            ext_address: br.ext_address.clone(),
            friendly_name: format!("{} ({})", br.network_name, br.rloc16),
            role: ThreadRole::from_ot_str(&br.state),
            lq_in: 3,
            lq_out: 3,
            matter_vendor: Some("OpenThread".to_string()),
            matter_product: Some("Border Router".to_string()),
            matter_state: Some(format!("CH {} · {}", br.channel, br.state.to_uppercase())),
            matter_clusters: vec!["ThreadNetworkDiagnostics".to_string()],
            ..Default::default()
        });
    } else if let Some(leader) = nodes.iter_mut().find(|n| n.role == ThreadRole::Leader) {
        if leader.matter_vendor.is_none() {
            leader.matter_vendor = Some("OpenThread".to_string());
            leader.matter_product = Some("Border Router (Leader)".to_string());
            leader.matter_state = Some(format!("CH {} · SRP {}", br.channel, br.srp_state));
            leader.matter_clusters = vec!["ThreadNetworkDiagnostics".to_string()];
            if !br_omr_prefix.is_empty() {
                leader.ipv6_omr = br_ipaddrs.iter().find(|a| !a.starts_with("fe80:") && !a.contains(":ff:fe00:")).cloned();
            }
        }
    }

    // Optional live python-matter-server WebSocket correlation
    let mut matter_connected = false;
    let mut matter_bluetooth_enabled = false;
    let mut matter_sdk = String::new();
    let mut matter_fabric = String::new();
    let mut matter_nodes = Vec::new();
    if let Some(ws_url) = &cfg.matter_ws_url {
        match fetch_matter_server_snapshot(ws_url, 4000) {
            Ok(ms) => {
                matter_connected = ms.connected;
                matter_bluetooth_enabled = ms.bluetooth_enabled;
                matter_sdk = ms.sdk_version;
                matter_fabric = ms.compressed_fabric_id;
                matter_nodes = ms.nodes;
                source_parts.push("Matter WS".to_string());
            }
            Err(e) => {
                if let Ok(mut s) = state.lock() {
                    s.push_event("WARN", "MATTER", "Matter WS poll failed", &json_str(&e));
                }
            }
        }
    }

    correlate_srp_and_matter(&mut nodes, &srp_services, &matter_nodes);

    if let Ok(mut snap) = state.lock() {
        let poll_now_s = now_epoch_s();
        for n in &mut nodes {
            n.last_seen_epoch_s = Some(if n.role == ThreadRole::Leader {
                poll_now_s
            } else {
                poll_now_s.saturating_sub(n.age_sec as u64)
            });
            if let Some(meta) = snap.node_meta.get(&n.ext_address) {
                if let Some(f) = &meta.friendly_name {
                    n.friendly_name = f.clone();
                }
                if meta.group.is_some() {
                    n.group = meta.group.clone();
                }
                if meta.description.is_some() {
                    n.description = meta.description.clone();
                }
                if meta.icon.is_some() {
                    n.icon = meta.icon.clone();
                }
                if meta.pairing_code.is_some() {
                    n.pairing_code = meta.pairing_code.clone();
                }
            } else if let Some(custom) = snap.friendly_names.get(&n.ext_address) {
                n.friendly_name = custom.clone();
            }
            n.health_score = compute_node_health_score(n);
            if n.role != ThreadRole::Leader && n.avg_rssi_dbm < 0 {
                let hist = snap.rssi_history_map.entry(n.ext_address.clone()).or_default();
                let sample = if n.last_rssi_dbm < 0 { n.last_rssi_dbm } else { n.avg_rssi_dbm };
                hist.push(sample);
                if hist.len() > cfg.rssi_history_points {
                    let excess = hist.len() - cfg.rssi_history_points;
                    hist.drain(0..excess);
                }
                n.rssi_history = hist.clone();
            }
        }

        let (mesh_health, health_issues) =
            analyze_mesh_health(&br, &nodes, &mac_counters, &ip_counters, cfg.zigbee_channel);
        let links = rebuild_mesh_links(&nodes, &br.rloc16);
        let correlated_n = nodes.iter().filter(|n| n.matter_node_id.is_some()).count();

        snap.updated_at_s = now_epoch_s();
        snap.demo_mode = false;
        snap.otbr_source = if source_parts.is_empty() {
            "otbr-disconnected".to_string()
        } else {
            source_parts.join(" + ")
        };
        snap.matter_connected = matter_connected;
        snap.matter_bluetooth_enabled = matter_bluetooth_enabled;
        snap.matter_sdk_version = matter_sdk;
        snap.matter_fabric_id = matter_fabric;
        snap.zigbee_channel = cfg.zigbee_channel;
        let omr_route_ok = check_ipv6_omr_route(&br_omr_prefix);
        snap.br = br;
        snap.br_ipaddrs = br_ipaddrs;
        snap.br_omr_prefix = br_omr_prefix;
        snap.ipv6_omr_route_ok = omr_route_ok;
        snap.mac_counters = mac_counters;
        snap.ip_counters = ip_counters;
        snap.srp_services = srp_services;
        snap.mesh_health_score = mesh_health;
        snap.health_issues = health_issues;
        let unmatched: Vec<String> = nodes
            .iter()
            .filter(|n| n.role != ThreadRole::Leader && n.matter_node_id.is_none())
            .map(|n| format!("{}({})", n.friendly_name, n.rloc16))
            .collect();
        snap.nodes = nodes;
        snap.links = links;

        if !unmatched.is_empty() {
            snap.push_event(
                "WARN",
                "UNMATCHED",
                &format!("{} Thread node(s) seen on radio without Matter L7 match", unmatched.len()),
                &format!("{{\"nodes\":{}}}", json_str(&unmatched.join(", "))),
            );
        }
        if omr_route_ok == Some(false) {
            let omr_payload = format!("{{\"omr_prefix\":{}}}", json_str(&snap.br_omr_prefix));
            snap.push_event(
                "WARN",
                "UNMATCHED",
                "Host Linux IPv6 route missing for Thread OMR prefix",
                &omr_payload,
            );
        }

        let summary = format!(
            "Mesh poll OK (CH {}, {} nodes, {} Matter L7, Health {}%)",
            snap.br.channel,
            snap.nodes.len(),
            correlated_n,
            snap.mesh_health_score
        );
        let payload = format!(
            "{{\"channel\":{},\"nodes\":{},\"matter_linked\":{},\"health\":{},\"ip_ok_pct\":{:.2}}}",
            snap.br.channel,
            snap.nodes.len(),
            correlated_n,
            snap.mesh_health_score,
            snap.ip_counters.delivery_rate_pct()
        );
        snap.push_event("INFO", "OTBR", &summary, &payload);
    }
}

fn publish_mqtt_cycle(cfg: &AppConfig, state: &Arc<Mutex<MeshSnapshot>>) {
    if !cfg.mqtt_enabled {
        return;
    }
    let Some(host) = &cfg.mqtt_host else {
        return;
    };
    let snap_copy = match state.lock() {
        Ok(s) => s.clone(),
        Err(_) => return,
    };
    match MqttPublisher::connect(
        host,
        "thread2mqtt-rust",
        cfg.mqtt_user.as_deref(),
        cfg.mqtt_pass.as_deref(),
        &cfg.mqtt_base_topic,
    ) {
        Ok(mut cli) => {
            let bt = cfg.mqtt_base_topic.trim_end_matches('/');
            let _ = cli.publish(&format!("{}/bridge/state", bt), "online", true);
            let info_json = format!(
                "{{\"state\":{},\"network_name\":{},\"channel\":{},\"pan_id\":{},\"nodes_count\":{},\"router_count\":{},\"health_score\":{}}}",
                json_str(&snap_copy.br.state),
                json_str(&snap_copy.br.network_name),
                snap_copy.br.channel,
                json_str(&snap_copy.br.pan_id),
                snap_copy.nodes.len(),
                snap_copy.br.router_count,
                snap_copy.mesh_health_score
            );
            let _ = cli.publish(&format!("{}/bridge/info", bt), &info_json, true);
            if cfg.ha_discovery_enabled {
                for (topic, payload) in
                    build_ha_discovery_payloads(&cfg.ha_discovery_prefix, bt, &snap_copy)
                {
                    let _ = cli.publish(&topic, &payload, true);
                }
            }
            for node in &snap_copy.nodes {
                let slug = sanitize_topic_slug(&node.ext_address);
                let _ = cli.publish(&format!("{}/node/{}", bt, slug), &node.to_json(), true);
            }
            if let Ok(mut s) = state.lock() {
                s.mqtt_connected = true;
                s.push_event(
                    "TX",
                    "MQTT",
                    &format!(
                        "Published HA Discovery & {} Thread node states to {}",
                        snap_copy.nodes.len(),
                        host
                    ),
                    &info_json,
                );
            }
        }
        Err(e) => {
            if let Ok(mut s) = state.lock() {
                s.mqtt_connected = false;
                s.push_event("WARN", "MQTT", "MQTT broker publish failed", &json_str(&e));
            }
        }
    }
}

fn write_http(mut stream: &TcpStream, status: &str, content_type: &str, body: &str) {
    let hdr = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        status,
        content_type,
        body.len()
    );
    let _ = stream.write_all(hdr.as_bytes());
    let _ = stream.write_all(body.as_bytes());
}

fn write_http_bytes(mut stream: &TcpStream, status: &str, content_type: &str, body: &[u8]) {
    let hdr = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nReferrer-Policy: no-referrer\r\nCache-Control: public, max-age=3600\r\nConnection: close\r\n\r\n",
        status,
        content_type,
        body.len()
    );
    let _ = stream.write_all(hdr.as_bytes());
    let _ = stream.write_all(body);
}

fn serve_local_device_image(stream: &TcpStream, cfg: &AppConfig, filename: &str) {
    let valid_name = !filename.is_empty()
        && filename.len() <= 96
        && !filename.contains("..")
        && !filename.contains('/')
        && !filename.contains('\\')
        && filename
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
    if !valid_name {
        write_http(stream, "400 Bad Request", "application/json", "{\"error\":\"Invalid image filename\"}");
        return;
    }
    let mime = match filename.rsplit('.').next().map(|s| s.to_ascii_lowercase()).as_deref() {
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("webp") => "image/webp",
        Some("svg") => "image/svg+xml",
        _ => {
            write_http(stream, "400 Bad Request", "application/json", "{\"error\":\"Unsupported image format\"}");
            return;
        }
    };
    const MAX_IMG_BYTES: u64 = 2 * 1024 * 1024;
    if let Some(dir) = cfg.data_dir.as_deref() {
        let path = Path::new(dir).join("device_images").join(filename);
        if let Ok(meta) = fs::metadata(&path) {
            if meta.is_file() && meta.len() <= MAX_IMG_BYTES {
                if let Ok(f) = File::open(&path) {
                    let mut bytes = Vec::with_capacity(meta.len() as usize);
                    if f.take(MAX_IMG_BYTES + 1).read_to_end(&mut bytes).is_ok()
                        && (bytes.len() as u64) <= MAX_IMG_BYTES
                    {
                        write_http_bytes(stream, "200 OK", mime, &bytes);
                        return;
                    }
                }
            }
        }
    }
    if let Some(embedded) = builtin_device_image(filename) {
        write_http_bytes(stream, "200 OK", "image/webp", embedded);
        return;
    }
    write_http(stream, "404 Not Found", "application/json", "{\"error\":\"Device image not found\"}");
}

/// Inspects a raw `python-matter-server` WebSocket JSON reply for `error_code` so
/// application-level Matter failures return HTTP 502 instead of false 200 OK.
fn write_matter_reply(stream: &TcpStream, raw_resp: &str) -> Result<(), String> {
    if let Some(val) = parse_json(raw_resp) {
        if let Some(err_code) = val.get("error_code").and_then(|v| v.as_i64()) {
            let details = val
                .get("details")
                .and_then(|v| v.as_str())
                .unwrap_or("Matter server error");
            let err_body = format!(
                "{{\"error\":{},\"error_code\":{},\"details\":{}}}",
                json_str(details),
                err_code,
                json_str(details)
            );
            write_http(stream, "502 Bad Gateway", "application/json", &err_body);
            return Err(format!("Matter error_code {}: {}", err_code, details));
        }
    }
    write_http(stream, "200 OK", "application/json", raw_resp);
    Ok(())
}

fn handle_sse(mut stream: TcpStream, state: Arc<Mutex<MeshSnapshot>>) {
    let Some(_sse_guard) = SlotGuard::try_acquire(&ACTIVE_SSE_CONNS, MAX_SSE_CONNS) else {
        write_http(
            &stream,
            "503 Service Unavailable",
            "application/json",
            "{\"error\":\"Too many active SSE streams\"}",
        );
        return;
    };
    let hdr = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nX-Content-Type-Options: nosniff\r\nConnection: keep-alive\r\n\r\n";
    if stream.write_all(hdr.as_bytes()).is_err() {
        return;
    }
    let mut last_seq = 0u64;
    for _ in 0..900 {
        let batch: Vec<String> = match state.lock() {
            Ok(s) => {
                let mut evs = Vec::new();
                for e in &s.events {
                    if e.seq > last_seq {
                        last_seq = e.seq;
                        evs.push(e.to_json());
                    }
                }
                evs
            }
            Err(_) => break,
        };
        for ev in batch {
            let frame = format!("data: {}\n\n", ev);
            if stream.write_all(frame.as_bytes()).is_err() {
                return;
            }
        }
        if stream.write_all(b": keepalive\n\n").is_err() || stream.flush().is_err() {
            return;
        }
        thread::sleep(Duration::from_secs(2));
    }
}

fn handle_client(stream: TcpStream, state: Arc<Mutex<MeshSnapshot>>, cfg: AppConfig) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(6)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let header_deadline = Instant::now() + Duration::from_secs(6);
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    let req_line = match read_bounded_line(&mut reader, MAX_HEADER_LINE_BYTES) {
        Ok(Some(l)) => l,
        Ok(None) => return,
        Err(()) => {
            write_http(&stream, "414 URI Too Long", "application/json", "{\"error\":\"Request line too large\"}");
            return;
        }
    };
    let parts: Vec<&str> = req_line.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }
    let method = parts[0];
    let path = parts[1].split('?').next().unwrap_or("/");

    let mut content_len: usize = 0;
    let mut header_token: Option<String> = None;
    let mut cookie_token: Option<String> = None;
    let mut host_hdr: Option<String> = None;
    let mut fwd_host_hdr: Option<String> = None;
    let mut origin_hdr: Option<String> = None;
    let mut content_type_hdr: Option<String> = None;
    let mut sec_fetch_site: Option<String> = None;
    let mut total_hdr_bytes: usize = req_line.len();
    let mut hdr_count: usize = 0;
    loop {
        if Instant::now() > header_deadline {
            write_http(&stream, "408 Request Timeout", "application/json", "{\"error\":\"Header read deadline exceeded\"}");
            return;
        }
        let h = match read_bounded_line(&mut reader, MAX_HEADER_LINE_BYTES) {
            Ok(Some(line)) => line,
            Ok(None) => break,
            Err(()) => {
                write_http(&stream, "431 Request Header Fields Too Large", "application/json", "{\"error\":\"Header line too large\"}");
                return;
            }
        };
        if h == "\r\n" || h == "\n" {
            break;
        }
        hdr_count += 1;
        total_hdr_bytes = total_hdr_bytes.saturating_add(h.len());
        if hdr_count > MAX_HEADERS_COUNT || total_hdr_bytes > MAX_HEADER_TOTAL_BYTES {
            write_http(&stream, "431 Request Header Fields Too Large", "application/json", "{\"error\":\"Too many or oversized headers\"}");
            return;
        }
        if let Some((k, v)) = h.split_once(':') {
            let val = v.trim();
            if k.eq_ignore_ascii_case("content-length") {
                content_len = val.parse::<usize>().unwrap_or(0).min(32768);
            } else if k.eq_ignore_ascii_case("host") {
                host_hdr = Some(val.to_string());
            } else if k.eq_ignore_ascii_case("x-forwarded-host") {
                fwd_host_hdr = Some(val.split(',').next().unwrap_or(val).trim().to_string());
            } else if k.eq_ignore_ascii_case("origin") {
                origin_hdr = Some(val.to_string());
            } else if k.eq_ignore_ascii_case("content-type") {
                content_type_hdr = Some(val.to_string());
            } else if k.eq_ignore_ascii_case("sec-fetch-site") {
                sec_fetch_site = Some(val.to_string());
            } else if k.eq_ignore_ascii_case("authorization") {
                if let Some(bearer) = val.strip_prefix("Bearer ").or_else(|| val.strip_prefix("bearer ")) {
                    header_token = Some(bearer.trim().to_string());
                }
            } else if k.eq_ignore_ascii_case("x-auth-token") {
                header_token = Some(val.to_string());
            } else if k.eq_ignore_ascii_case("cookie") && cookie_token.is_none() {
                for kv in val.split(';') {
                    if let Some(tok) = kv.trim().strip_prefix("t2m_auth=") {
                        cookie_token = Some(tok.trim().to_string());
                        break;
                    }
                }
            }
        }
    }
    let mut body = String::new();
    if content_len > 0 {
        let mut buf = vec![0u8; content_len];
        if reader.read_exact(&mut buf).is_ok() {
            body = String::from_utf8_lossy(&buf).to_string();
        }
    }

    // CSRF protection on all state-changing/action POST routes
    if method == "POST" {
        let _ = stream.set_write_timeout(Some(Duration::from_secs(20)));
        if sec_fetch_site
            .as_deref()
            .map(|s| s.eq_ignore_ascii_case("cross-site"))
            .unwrap_or(false)
        {
            write_http(&stream, "403 Forbidden", "application/json", "{\"error\":\"Cross-site POST blocked (CSRF protection)\"}");
            return;
        }
        if let Some(orig) = origin_hdr.as_deref() {
            let orig_auth = origin_authority(orig);
            let host_ok = match (orig_auth, host_hdr.as_deref(), fwd_host_hdr.as_deref()) {
                (Some(oa), Some(h), _) if oa.eq_ignore_ascii_case(h) => true,
                (Some(oa), _, Some(fh)) if oa.eq_ignore_ascii_case(fh) => true,
                _ => false,
            };
            if !host_ok {
                write_http(&stream, "403 Forbidden", "application/json", "{\"error\":\"Origin mismatch blocked (CSRF protection)\"}");
                return;
            }
        }
        let ct_json = content_type_hdr
            .as_deref()
            .map(|ct| ct.to_ascii_lowercase().contains("application/json"))
            .unwrap_or(false);
        if !ct_json {
            write_http(
                &stream,
                "415 Unsupported Media Type",
                "application/json",
                "{\"error\":\"Content-Type: application/json required for POST requests\"}",
            );
            return;
        }
    }

    // Optional frontend.auth_token enforcement (cookie accepted only for GET/HEAD, never POST)
    let provided_token = if matches!(method, "GET" | "HEAD") {
        header_token.or(cookie_token)
    } else {
        header_token
    };
    let is_public_shell = matches!(
        (method, path),
        ("GET", "/")
            | ("GET", "/index.html")
            | ("HEAD", "/")
            | ("HEAD", "/index.html")
            | ("GET", "/logo.png")
            | ("HEAD", "/logo.png")
            | ("GET", "/health")
            | ("HEAD", "/health")
    );
    if !is_public_shell {
        if let Some(expected) = &cfg.auth_token {
            let ok = provided_token.as_deref().map(|p| ct_eq(p, expected)).unwrap_or(false);
            if !ok {
                write_http(
                    &stream,
                    "401 Unauthorized",
                    "application/json",
                    "{\"error\":\"Authentication required (set Authorization: Bearer <token> or X-Auth-Token)\",\"auth_required\":true}",
                );
                return;
            }
        }
    }

    match (method, path) {
        ("HEAD", "/") | ("HEAD", "/index.html") => {
            write_http(&stream, "200 OK", "text/html; charset=utf-8", "");
        }
        ("HEAD", "/logo.png") => {
            write_http_bytes(&stream, "200 OK", "image/png", b"");
        }
        ("GET", "/logo.png") => {
            write_http_bytes(&stream, "200 OK", "image/png", EMBEDDED_LOGO_PNG);
        }
        ("HEAD", "/health") => {
            write_http(&stream, "200 OK", "application/json", "");
        }
        ("GET", "/") | ("GET", "/index.html") => {
            write_http(&stream, "200 OK", "text/html; charset=utf-8", EMBEDDED_UI_HTML);
        }
        ("GET", "/health") => {
            write_http(
                &stream,
                "200 OK",
                "application/json",
                &format!(
                    "{{\"status\":\"ok\",\"service\":\"thread2mqtt\",\"version\":{}}}",
                    json_str(env!("CARGO_PKG_VERSION"))
                ),
            );
        }
        ("GET", "/api/config") => {
            write_http(&stream, "200 OK", "application/json", &cfg.to_public_json());
        }
        ("GET", "/api/state") => {
            let payload = state
                .lock()
                .map(|s| s.to_json())
                .unwrap_or_else(|_| "{}".to_string());
            write_http(&stream, "200 OK", "application/json", &payload);
        }
        ("GET", "/api/demo-state") => {
            let demo = build_demo_snapshot();
            write_http(&stream, "200 OK", "application/json", &demo.to_json());
        }
        ("GET", "/api/hardware/scan") => {
            let matter_bt = state.lock().map(|s| s.matter_bluetooth_enabled).unwrap_or(false);
            let payload = scan_local_hardware(cfg.demo_mode, matter_bt);
            write_http(&stream, "200 OK", "application/json", &payload);
        }
        ("GET", "/api/discovery") => {
            let payload = match state.lock() {
                Ok(s) => {
                    let items: Vec<String> =
                        build_ha_discovery_payloads(&cfg.ha_discovery_prefix, &cfg.mqtt_base_topic, &s)
                            .into_iter()
                            .map(|(t, p)| format!("{{\"topic\":{},\"payload\":{}}}", json_str(&t), p))
                            .collect();
                    format!("{{\"count\":{},\"items\":[{}]}}", items.len(), items.join(","))
                }
                Err(_) => "{\"count\":0,\"items\":[]}".to_string(),
            };
            write_http(&stream, "200 OK", "application/json", &payload);
        }
        ("GET", "/api/backup") | ("GET", "/api/support-bundle") => {
            let payload = state
                .lock()
                .map(|s| sanitize_mqtt_payload(&s.to_json()))
                .unwrap_or_else(|_| "{}".to_string());
            write_http(&stream, "200 OK", "application/json", &payload);
        }
        ("GET", "/metrics") => {
            let prom = state
                .lock()
                .map(|s| render_prometheus_metrics(&s))
                .unwrap_or_default();
            write_http(&stream, "200 OK", "text/plain; version=0.0.4; charset=utf-8", &prom);
        }
        ("GET", "/api/alerts") => {
            let payload = state
                .lock()
                .map(|s| {
                    let active: Vec<String> = s
                        .health_issues
                        .iter()
                        .filter(|i| i.severity != "ok")
                        .map(|i| i.to_json())
                        .collect();
                    format!(
                        "{{\"status\":{},\"health_score\":{},\"active_count\":{},\"alerts\":[{}]}}",
                        json_str(if active.is_empty() { "ok" } else { "degraded" }),
                        s.mesh_health_score,
                        active.len(),
                        active.join(",")
                    )
                })
                .unwrap_or_else(|_| "{\"status\":\"unknown\",\"active_count\":0,\"alerts\":[]}".to_string());
            write_http(&stream, "200 OK", "application/json", &payload);
        }
        ("GET", p) if p.starts_with("/device-images/") => {
            serve_local_device_image(&stream, &cfg, &p["/device-images/".len()..]);
        }
        ("GET", "/api/events") => {
            handle_sse(stream, state);
        }
        ("POST", "/api/poll-now") => {
            if !cfg.demo_mode {
                poll_live_otbr(&cfg, &state);
            }
            write_http(&stream, "200 OK", "application/json", "{\"status\":\"ok\"}");
        }
        ("POST", "/api/pairing-code/reveal") => {
            let Some(val) = parse_json(&body) else {
                write_http(&stream, "400 Bad Request", "application/json", "{\"error\":\"Invalid JSON body\"}");
                return;
            };
            let ext = val
                .get("ext_address")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_ascii_lowercase());
            match ext {
                Some(e) if e.len() == 16 && e.chars().all(|c| c.is_ascii_hexdigit()) => {
                    let found = state.lock().ok().and_then(|mut s| {
                        let node_code = s
                            .nodes
                            .iter()
                            .find(|nd| nd.ext_address == e)
                            .and_then(|nd| nd.pairing_code.clone());
                        let code = s
                            .node_meta
                            .get(&e)
                            .and_then(|m| m.pairing_code.clone())
                            .or(node_code);
                        if code.is_some() {
                            s.push_event(
                                "INFO",
                                "HTTP",
                                &format!("Revealed local pairing code memo for node {}", e),
                                &format!("{{\"ext_address\":{}}}", json_str(&e)),
                            );
                        }
                        code
                    });
                    if let Some(code) = found {
                        write_http(
                            &stream,
                            "200 OK",
                            "application/json",
                            &format!("{{\"ext_address\":{},\"pairing_code\":{}}}", json_str(&e), json_str(&code)),
                        );
                    } else {
                        write_http(&stream, "404 Not Found", "application/json", "{\"error\":\"No pairing code memo saved for this node\"}");
                    }
                }
                _ => {
                    write_http(&stream, "400 Bad Request", "application/json", "{\"error\":\"Invalid ext_address (16 hex)\"}");
                }
            }
        }
        ("POST", "/api/rename") | ("POST", "/api/node-meta") => {
            let Some(val) = parse_json(&body) else {
                write_http(&stream, "400 Bad Request", "application/json", "{\"error\":\"Invalid JSON body\"}");
                return;
            };
            let ext = val
                .get("ext_address")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_ascii_lowercase());
            let name = val
                .get("friendly_name")
                .and_then(|v| v.as_str())
                .and_then(sanitize_friendly_name);
            let has_group = val.get("group").is_some();
            let has_desc = val.get("description").is_some();
            let has_icon = val.get("icon").is_some();
            let has_pairing = val.get("pairing_code").is_some();
            let sync_ha = val.get("sync_ha").and_then(|v| v.as_bool()).unwrap_or(false);
            let group = val
                .get("group")
                .and_then(|v| v.as_str())
                .and_then(sanitize_friendly_name);
            let desc = val
                .get("description")
                .and_then(|v| v.as_str())
                .and_then(sanitize_friendly_name);
            let pairing_code = val
                .get("pairing_code")
                .and_then(|v| v.as_str())
                .and_then(sanitize_pairing_code);
            let icon = val
                .get("icon")
                .and_then(|v| v.as_str())
                .and_then(sanitize_local_icon);
            match ext {
                Some(e) if e.len() == 16 && e.chars().all(|c| c.is_ascii_hexdigit()) && (name.is_some() || has_group || has_desc || has_icon || has_pairing) => {
                    let mut saved_store: Option<BTreeMap<String, NodeMeta>> = None;
                    let mut target_matter_nid: Option<u32> = None;
                    let mut target_serial: Option<String> = None;
                    let mut fabric_id = String::new();
                    let mut node_known = false;
                    let mut store_full = false;
                    if let Ok(mut s) = state.lock() {
                        node_known = s.nodes.iter().any(|nd| nd.ext_address == e);
                        if node_known {
                            if !s.node_meta.contains_key(&e) && s.node_meta.len() >= MAX_NODE_META_ENTRIES {
                                store_full = true;
                            } else {
                                fabric_id = s.matter_fabric_id.clone();
                                {
                                    let entry = s.node_meta.entry(e.clone()).or_default();
                                    if let Some(n) = &name {
                                        entry.friendly_name = Some(n.clone());
                                    }
                                    if has_group {
                                        entry.group = group.clone();
                                    }
                                    if has_desc {
                                        entry.description = desc.clone();
                                    }
                                    if has_icon {
                                        entry.icon = icon.clone();
                                    }
                                    if has_pairing {
                                        entry.pairing_code = pairing_code.clone();
                                    }
                                }
                                if let Some(n) = &name {
                                    s.friendly_names.insert(e.clone(), n.clone());
                                }
                                if let Some(node) = s.nodes.iter_mut().find(|nd| nd.ext_address == e) {
                                    if let Some(n) = &name {
                                        node.friendly_name = n.clone();
                                    }
                                    if has_group {
                                        node.group = group.clone();
                                    }
                                    if has_desc {
                                        node.description = desc.clone();
                                    }
                                    if has_icon {
                                        node.icon = icon.clone();
                                    }
                                    if has_pairing {
                                        node.pairing_code = pairing_code.clone();
                                    }
                                    target_matter_nid = node.matter_node_id;
                                    target_serial = node.matter_serial.clone();
                                }
                                s.push_event(
                                    "INFO",
                                    "HTTP",
                                    &format!("Updated metadata for node {}", e),
                                    &format!(
                                        "{{\"ext_address\":{},\"friendly_name\":{},\"group\":{},\"sync_ha\":{}}}",
                                        json_str(&e),
                                        name.as_deref().map(json_str).unwrap_or_else(|| "null".into()),
                                        group.as_deref().map(json_str).unwrap_or_else(|| "null".into()),
                                        sync_ha
                                    ),
                                );
                                saved_store = Some(s.node_meta.clone());
                            }
                        }
                    }
                    if !node_known {
                        write_http(
                            &stream,
                            "404 Not Found",
                            "application/json",
                            "{\"error\":\"Unknown Thread node ext_address\"}",
                        );
                        return;
                    }
                    if store_full {
                        write_http(
                            &stream,
                            "400 Bad Request",
                            "application/json",
                            "{\"error\":\"Node metadata store capacity limit (512) reached\"}",
                        );
                        return;
                    }
                    let persisted = match (&cfg.data_dir, &saved_store) {
                        (Some(dir), Some(store)) => match save_node_meta_store(dir, store) {
                            Ok(()) => true,
                            Err(err) => {
                                if let Ok(mut s) = state.lock() {
                                    s.push_event("WARN", "HTTP", "Failed to persist state.json", &json_str(&err));
                                }
                                false
                            }
                        },
                        _ => false,
                    };
                    let mut matter_synced = false;
                    let mut ha_synced = false;
                    let mut ha_note: Option<String> = None;
                    if sync_ha {
                        if let Some(new_name) = &name {
                            if cfg.read_only_mode {
                                ha_note = Some("Mode lecture seule actif (read_only_mode: true) : renommage enregistré uniquement dans Thread2MQTT. Passez read_only_mode: false + homeassistant.allow_rename: true dans configuration.yaml pour synchroniser Home Assistant.".to_string());
                            } else {
                                if let (Some(ws), Some(nid)) = (&cfg.matter_ws_url, target_matter_nid) {
                                    if let Ok(resp) = matter_set_node_label(ws, nid as u64, new_name, 5000) {
                                        if !resp.contains("\"error_code\"") {
                                            matter_synced = true;
                                        }
                                    }
                                }
                                if cfg.can_sync_ha_rename() {
                                    if let (Some(ha_url), Some(ha_tok), Some(nid)) =
                                        (&cfg.ha_url, &cfg.ha_token, target_matter_nid)
                                    {
                                        match ha_rename_matter_device(
                                            ha_url,
                                            ha_tok,
                                            &fabric_id,
                                            nid as u64,
                                            target_serial.as_deref(),
                                            new_name,
                                            6000,
                                        ) {
                                            Ok(dev_id) => {
                                                ha_synced = true;
                                                if let Ok(mut s) = state.lock() {
                                                    s.push_event(
                                                        "INFO",
                                                        "MATTER",
                                                        &format!("Synced device name '{}' to Home Assistant ({})", new_name, dev_id),
                                                        &format!("{{\"matter_node_id\":{},\"ha_device_id\":{}}}", nid, json_str(&dev_id)),
                                                    );
                                                }
                                            }
                                            Err(err) => {
                                                ha_note = Some(err.clone());
                                                if let Ok(mut s) = state.lock() {
                                                    s.push_event("WARN", "MATTER", "Home Assistant rename sync failed", &json_str(&err));
                                                }
                                            }
                                        }
                                    } else {
                                        ha_note = Some("Ce nœud n'est pas lié à un Matter Node ID dans Home Assistant (nœud Thread seul).".to_string());
                                    }
                                } else {
                                    ha_note = Some("Synchronisation HA non configurée : ajoutez homeassistant.url, homeassistant.token et homeassistant.allow_rename: true dans configuration.yaml.".to_string());
                                }
                                if cfg.mqtt_enabled {
                                    let bg_c = cfg.clone();
                                    let bg_s = Arc::clone(&state);
                                    let _ = thread::Builder::new()
                                        .name("t2m-mqtt-sync".to_string())
                                        .spawn(move || publish_mqtt_cycle(&bg_c, &bg_s));
                                }
                            }
                        }
                    }
                    write_http(
                        &stream,
                        "200 OK",
                        "application/json",
                        &format!(
                            "{{\"status\":\"ok\",\"persisted\":{},\"matter_synced\":{},\"ha_synced\":{},\"ha_note\":{}}}",
                            persisted,
                            matter_synced,
                            ha_synced,
                            ha_note.as_deref().map(json_str).unwrap_or_else(|| "null".to_string())
                        ),
                    );
                }
                _ => {
                    write_http(
                        &stream,
                        "400 Bad Request",
                        "application/json",
                        "{\"error\":\"Invalid ext_address (16 hex) or empty metadata\"}",
                    );
                }
            }
        }
        ("POST", "/api/decode-matter") => {
            let code = json_get_str(&body, "code").unwrap_or_default();
            match decode_matter_setup_code(&code) {
                Ok(decoded) => {
                    write_http(&stream, "200 OK", "application/json", &decoded.to_json());
                }
                Err(err) => {
                    write_http(
                        &stream,
                        "400 Bad Request",
                        "application/json",
                        &format!("{{\"error\":{}}}", json_str(&err)),
                    );
                }
            }
        }
        ("POST", "/api/otctl") => {
            let cmd = json_get_str(&body, "command").unwrap_or_default();
            if !is_whitelisted_otctl(&cmd) {
                write_http(
                    &stream,
                    "403 Forbidden",
                    "application/json",
                    "{\"error\":\"Command blocked by Zero-Trust read-only whitelist\"}",
                );
                return;
            }
            if let Some(otctl) = &cfg.otctl_cmd {
                match run_otctl(otctl, &cmd) {
                    Ok(out) => {
                        let safe_out = sanitize_mqtt_payload(&out);
                        if let Ok(mut s) = state.lock() {
                            s.push_event("INFO", "DEV", &format!("Dev Console ran `ot-ctl {}`", cmd), "{}");
                        }
                        write_http(
                            &stream,
                            "200 OK",
                            "application/json",
                            &format!("{{\"command\":{},\"output\":{}}}", json_str(&cmd), json_str(&safe_out)),
                        );
                    }
                    Err(e) => {
                        write_http(
                            &stream,
                            "502 Bad Gateway",
                            "application/json",
                            &format!("{{\"error\":{}}}", json_str(&e)),
                        );
                    }
                }
            } else {
                write_http(
                    &stream,
                    "200 OK",
                    "application/json",
                    &format!(
                        "{{\"command\":{},\"output\":\"Demo mode active (configure OTCTL_CMD for live Border Router execution).\"}}",
                        json_str(&cmd)
                    ),
                );
            }
        }
        ("POST", "/api/energy-scan") => {
            if let Some(otctl) = &cfg.otctl_cmd {
                match run_otctl(otctl, "scan energy 100") {
                    Ok(raw) => {
                        let channels = parse_otctl_energy_scan(&raw);
                        let items = channels.iter().map(|c| c.to_json()).collect::<Vec<_>>().join(",");
                        if let Ok(mut s) = state.lock() {
                            s.energy_scan = channels;
                            s.push_event("INFO", "RF", "IEEE 802.15.4 16-channel RF Energy Scan completed", "{}");
                        }
                        write_http(
                            &stream,
                            "200 OK",
                            "application/json",
                            &format!("{{\"status\":\"ok\",\"channels\":[{}]}}", items),
                        );
                    }
                    Err(e) => {
                        write_http(
                            &stream,
                            "502 Bad Gateway",
                            "application/json",
                            &format!("{{\"error\":{}}}", json_str(&e)),
                        );
                    }
                }
            } else {
                let demo = build_demo_snapshot();
                let items = demo.energy_scan.iter().map(|c| c.to_json()).collect::<Vec<_>>().join(",");
                write_http(
                    &stream,
                    "200 OK",
                    "application/json",
                    &format!("{{\"status\":\"demo\",\"channels\":[{}]}}", items),
                );
            }
        }
        ("POST", "/api/matter-ping") => {
            let nid = json_get_i64(&body, "node_id").unwrap_or(0);
            if nid <= 0 {
                write_http(&stream, "400 Bad Request", "application/json", "{\"error\":\"Missing node_id\"}");
                return;
            }
            if let Some(ws) = &cfg.matter_ws_url {
                match matter_ping_node(ws, nid as u64, 5000) {
                    Ok(resp) => match write_matter_reply(&stream, &resp) {
                        Ok(()) => {
                            if let Ok(mut s) = state.lock() {
                                s.push_event("INFO", "MATTER", &format!("Matter Ping Node #{} OK", nid), &resp);
                            }
                        }
                        Err(err) => {
                            if let Ok(mut s) = state.lock() {
                                s.push_event("WARN", "MATTER", &format!("Matter Ping Node #{} failed", nid), &json_str(&err));
                            }
                        }
                    },
                    Err(e) => {
                        write_http(
                            &stream,
                            "502 Bad Gateway",
                            "application/json",
                            &format!("{{\"error\":{}}}", json_str(&e)),
                        );
                    }
                }
            } else {
                write_http(
                    &stream,
                    "200 OK",
                    "application/json",
                    &format!("{{\"result\":{{\"fd00:db8:cafe:1::{}\":true}},\"demo\":true}}", nid),
                );
            }
        }
        ("POST", "/api/matter-discover") => {
            if let Some(ws) = &cfg.matter_ws_url {
                match matter_discover_commissionable(ws, 12000) {
                    Ok(resp) => match write_matter_reply(&stream, &resp) {
                        Ok(()) => {
                            if let Ok(mut s) = state.lock() {
                                s.push_event("INFO", "MATTER", "Commissionable mDNS discovery completed", "{}");
                            }
                        }
                        Err(err) => {
                            if let Ok(mut s) = state.lock() {
                                s.push_event("WARN", "MATTER", "Commissionable mDNS discovery failed", &json_str(&err));
                            }
                        }
                    },
                    Err(e) => {
                        write_http(
                            &stream,
                            "502 Bad Gateway",
                            "application/json",
                            &format!("{{\"error\":{}}}", json_str(&e)),
                        );
                    }
                }
            } else {
                write_http(
                    &stream,
                    "200 OK",
                    "application/json",
                    "{\"result\":[{\"instance_name\":\"DEMO-MATTER-001\",\"vendor_id\":65521,\"product_id\":32768,\"long_discriminator\":3840,\"device_name\":\"Demo Thread Plug (Ready to Join)\"}],\"demo\":true}",
                );
            }
        }
        ("POST", "/api/matter-ota-check") => {
            let nid = json_get_i64(&body, "node_id").unwrap_or(0);
            if nid <= 0 {
                write_http(&stream, "400 Bad Request", "application/json", "{\"error\":\"Missing node_id\"}");
                return;
            }
            if !cfg.allow_ota_check {
                write_http(&stream, "403 Forbidden", "application/json", "{\"error\":\"OTA check disabled in configuration.yaml\"}");
                return;
            }
            if let Some(ws) = &cfg.matter_ws_url {
                match matter_check_node_update(ws, nid as u64, 15000) {
                    Ok(resp) => match write_matter_reply(&stream, &resp) {
                        Ok(()) => {
                            if let Ok(mut s) = state.lock() {
                                s.push_event("INFO", "MATTER", &format!("OTA CSA DCL check Node #{}", nid), &resp);
                            }
                        }
                        Err(err) => {
                            if let Ok(mut s) = state.lock() {
                                s.push_event("WARN", "MATTER", &format!("OTA check Node #{} failed", nid), &json_str(&err));
                            }
                        }
                    },
                    Err(e) => {
                        write_http(
                            &stream,
                            "502 Bad Gateway",
                            "application/json",
                            &format!("{{\"error\":{}}}", json_str(&e)),
                        );
                    }
                }
            } else {
                write_http(
                    &stream,
                    "200 OK",
                    "application/json",
                    "{\"result\":null,\"up_to_date\":true,\"demo\":true}",
                );
            }
        }
        ("POST", "/api/matter-commission") => {
            if !cfg.can_commission() {
                write_http(
                    &stream,
                    "403 Forbidden",
                    "application/json",
                    "{\"error\":\"Commissioning bloqué par sécurité (read_only_mode=true ou allow_commissioning=false). Activez advanced.read_only_mode: false et matter.allow_commissioning: true dans configuration.yaml.\",\"read_only_mode\":true}",
                );
                return;
            }
            let code = json_get_str(&body, "code").unwrap_or_default();
            let network_only = json_get_bool(&body, "network_only").unwrap_or(false);
            if let Err(err) = decode_matter_setup_code(&code) {
                write_http(
                    &stream,
                    "400 Bad Request",
                    "application/json",
                    &format!("{{\"error\":{}}}", json_str(&format!("Invalid Matter setup code: {}", err))),
                );
                return;
            }
            if let Some(ws) = &cfg.matter_ws_url {
                match matter_commission_with_code(ws, &code, network_only, 90000) {
                    Ok(resp) => match write_matter_reply(&stream, &resp) {
                        Ok(()) => {
                            if let Ok(mut s) = state.lock() {
                                s.push_event("INFO", "MATTER", "New Matter-over-Thread device commissioned via UI", "{}");
                            }
                            if !cfg.demo_mode {
                                poll_live_otbr(&cfg, &state);
                            }
                        }
                        Err(err) => {
                            if let Ok(mut s) = state.lock() {
                                s.push_event("WARN", "MATTER", "Matter commissioning failed", &json_str(&err));
                            }
                        }
                    },
                    Err(e) => {
                        write_http(
                            &stream,
                            "502 Bad Gateway",
                            "application/json",
                            &format!("{{\"error\":{}}}", json_str(&e)),
                        );
                    }
                }
            } else {
                write_http(
                    &stream,
                    "400 Bad Request",
                    "application/json",
                    "{\"error\":\"matter.ws_url not configured in configuration.yaml\"}",
                );
            }
        }
        ("POST", "/api/matter-ecw") => {
            if !cfg.can_commission() {
                write_http(
                    &stream,
                    "403 Forbidden",
                    "application/json",
                    "{\"error\":\"Fenêtre Multi-Admin (ECW) bloquée en mode lecture seule. Passez advanced.read_only_mode: false et matter.allow_commissioning: true dans configuration.yaml.\",\"read_only_mode\":true}",
                );
                return;
            }
            let nid = json_get_i64(&body, "node_id").unwrap_or(0);
            let timeout = json_get_i64(&body, "timeout").unwrap_or(300) as u32;
            if nid <= 0 {
                write_http(&stream, "400 Bad Request", "application/json", "{\"error\":\"Missing node_id\"}");
                return;
            }
            if let Some(ws) = &cfg.matter_ws_url {
                match matter_open_commissioning_window(ws, nid as u64, timeout, 15000) {
                    Ok(resp) => match write_matter_reply(&stream, &resp) {
                        Ok(()) => {
                            if let Ok(mut s) = state.lock() {
                                s.push_event("INFO", "MATTER", &format!("Opened Multi-Admin ECW ({}s) for Node #{}", timeout, nid), "{}");
                            }
                        }
                        Err(err) => {
                            if let Ok(mut s) = state.lock() {
                                s.push_event("WARN", "MATTER", &format!("Multi-Admin ECW Node #{} failed", nid), &json_str(&err));
                            }
                        }
                    },
                    Err(e) => {
                        write_http(
                            &stream,
                            "502 Bad Gateway",
                            "application/json",
                            &format!("{{\"error\":{}}}", json_str(&e)),
                        );
                    }
                }
            } else {
                write_http(&stream, "400 Bad Request", "application/json", "{\"error\":\"matter.ws_url not configured\"}");
            }
        }
        ("POST", "/api/matter-interview") => {
            if !cfg.can_interview() {
                write_http(
                    &stream,
                    "403 Forbidden",
                    "application/json",
                    "{\"error\":\"Interview bloquée en mode lecture seule (read_only_mode=true dans configuration.yaml).\",\"read_only_mode\":true}",
                );
                return;
            }
            let nid = json_get_i64(&body, "node_id").unwrap_or(0);
            if nid <= 0 {
                write_http(&stream, "400 Bad Request", "application/json", "{\"error\":\"Missing node_id\"}");
                return;
            }
            if let Some(ws) = &cfg.matter_ws_url {
                match matter_interview_node(ws, nid as u64, 20000) {
                    Ok(resp) => match write_matter_reply(&stream, &resp) {
                        Ok(()) => {
                            if let Ok(mut s) = state.lock() {
                                s.push_event("INFO", "MATTER", &format!("Re-interviewed Matter Node #{}", nid), "{}");
                            }
                            if !cfg.demo_mode {
                                poll_live_otbr(&cfg, &state);
                            }
                        }
                        Err(err) => {
                            if let Ok(mut s) = state.lock() {
                                s.push_event("WARN", "MATTER", &format!("Re-interview Node #{} failed", nid), &json_str(&err));
                            }
                        }
                    },
                    Err(e) => {
                        write_http(
                            &stream,
                            "502 Bad Gateway",
                            "application/json",
                            &format!("{{\"error\":{}}}", json_str(&e)),
                        );
                    }
                }
            } else {
                write_http(&stream, "400 Bad Request", "application/json", "{\"error\":\"matter.ws_url not configured\"}");
            }
        }
        ("POST", "/api/matter-command") => {
            if cfg.read_only_mode {
                write_http(
                    &stream,
                    "403 Forbidden",
                    "application/json",
                    "{\"error\":\"Commandes Matter bloquées en mode lecture seule (read_only_mode=true dans configuration.yaml).\",\"read_only_mode\":true}",
                );
                return;
            }
            let nid = json_get_i64(&body, "node_id").unwrap_or(0);
            let ep = json_get_i64(&body, "endpoint_id").unwrap_or(1).clamp(0, 255) as u16;
            let action = json_get_str(&body, "action").unwrap_or_default().to_ascii_lowercase();
            if nid <= 0 || action.is_empty() {
                write_http(&stream, "400 Bad Request", "application/json", "{\"error\":\"Missing node_id or action (identify|on|off|toggle)\"}");
                return;
            }
            let Some(ws) = &cfg.matter_ws_url else {
                write_http(&stream, "400 Bad Request", "application/json", "{\"error\":\"matter.ws_url not configured\"}");
                return;
            };
            let res = match action.as_str() {
                "identify" => {
                    let secs = json_get_i64(&body, "seconds").unwrap_or(5).clamp(1, 30) as u16;
                    matter_identify_node(ws, nid as u64, ep, secs, 10000)
                }
                "on" | "off" | "toggle" => matter_set_onoff(ws, nid as u64, ep, &action, 10000),
                _ => {
                    write_http(&stream, "400 Bad Request", "application/json", "{\"error\":\"Unsupported action (allowed: identify, on, off, toggle)\"}");
                    return;
                }
            };
            match res {
                Ok(resp) => match write_matter_reply(&stream, &resp) {
                    Ok(()) => {
                        if let Ok(mut s) = state.lock() {
                            s.push_event("INFO", "MATTER", &format!("Executed `{}` on Node #{} ep {}", action, nid, ep), "{}");
                        }
                        if !cfg.demo_mode && action != "identify" {
                            poll_live_otbr(&cfg, &state);
                        }
                    }
                    Err(err) => {
                        if let Ok(mut s) = state.lock() {
                            s.push_event("WARN", "MATTER", &format!("Command `{}` on Node #{} failed", action, nid), &json_str(&err));
                        }
                    }
                },
                Err(e) => {
                    write_http(&stream, "502 Bad Gateway", "application/json", &format!("{{\"error\":{}}}", json_str(&e)));
                }
            }
        }
        _ => {
            write_http(&stream, "404 Not Found", "application/json", "{\"error\":\"Not found\"}");
        }
    }
}

fn main() {
    let cfg = AppConfig::load();
    let mut persisted = cfg.yaml_devices.clone();
    if let Some(dir) = cfg.data_dir.as_deref() {
        for (k, v) in load_node_meta_store(dir) {
            persisted.insert(k, v);
        }
    }

    let mut initial = if cfg.demo_mode {
        build_demo_snapshot()
    } else {
        MeshSnapshot {
            updated_at_s: now_epoch_s(),
            demo_mode: false,
            otbr_source: "connecting...".to_string(),
            mqtt_connected: false,
            matter_connected: false,
            matter_bluetooth_enabled: false,
            matter_sdk_version: String::new(),
            matter_fabric_id: String::new(),
            zigbee_channel: cfg.zigbee_channel,
            br: BorderRouterInfo::default(),
            br_ipaddrs: Vec::new(),
            br_omr_prefix: String::new(),
            ipv6_omr_route_ok: None,
            mac_counters: MacCounters::default(),
            ip_counters: IpCounters::default(),
            srp_services: Vec::new(),
            energy_scan: Vec::new(),
            mesh_health_score: 100,
            health_issues: Vec::new(),
            nodes: Vec::new(),
            links: Vec::new(),
            friendly_names: BTreeMap::new(),
            node_meta: BTreeMap::new(),
            rssi_history_map: BTreeMap::new(),
            events: Vec::new(),
        }
    };
    for (k, v) in &persisted {
        if let Some(f) = &v.friendly_name {
            initial.friendly_names.insert(k.clone(), f.clone());
        }
    }
    initial.node_meta = persisted;
    let state = Arc::new(Mutex::new(initial));

    let poller_state = Arc::clone(&state);
    let bg_cfg = cfg.clone();
    thread::spawn(move || {
        let mut tick: u64 = 0;
        loop {
            if !bg_cfg.demo_mode {
                poll_live_otbr(&bg_cfg, &poller_state);
            } else if tick > 0 {
                if let Ok(mut s) = poller_state.lock() {
                    let now_s = now_epoch_s();
                    s.updated_at_s = now_s;
                    for (idx, n) in s.nodes.iter_mut().enumerate() {
                        if idx == 0 {
                            n.age_sec = 0;
                            n.last_seen_epoch_s = Some(now_s);
                        } else {
                            let jitter = ((tick as i32 + idx as i32) % 3) - 1;
                            n.last_rssi_dbm = (n.avg_rssi_dbm + jitter).clamp(-96, -35);
                            n.age_sec = ((tick * bg_cfg.poll_secs) as u32 + (idx as u32 * 7)) % 55 + 2;
                            n.last_seen_epoch_s = Some(now_s.saturating_sub(n.age_sec as u64));
                            n.rssi_history.push(n.last_rssi_dbm);
                            if n.rssi_history.len() > bg_cfg.rssi_history_points {
                                n.rssi_history.remove(0);
                            }
                        }
                    }
                    let n_len = s.nodes.len();
                    s.push_event(
                        "INFO",
                        "OTBR",
                        "Demo mesh heartbeat — LQI/RSSI telemetry refreshed",
                        &format!("{{\"tick\":{},\"nodes\":{}}}", tick, n_len),
                    );
                }
            }
            publish_mqtt_cycle(&bg_cfg, &poller_state);
            tick += 1;
            thread::sleep(Duration::from_secs(bg_cfg.poll_secs));
        }
    });

    let listener = TcpListener::bind(&cfg.bind_addr)
        .unwrap_or_else(|e| panic!("Thread2MQTT bind {} failed: {}", cfg.bind_addr, e));
    println!(
        "[Thread2MQTT v{}] Listening on http://{} (demo={}, read_only={}, commissioning={}, otbr={}, matter={}, mqtt={})",
        env!("CARGO_PKG_VERSION"),
        cfg.bind_addr,
        cfg.demo_mode,
        cfg.read_only_mode,
        cfg.can_commission(),
        cfg.otbr_url.as_deref().unwrap_or("none"),
        cfg.matter_ws_url.as_deref().unwrap_or("disabled"),
        if cfg.mqtt_enabled { cfg.mqtt_host.as_deref().unwrap_or("disabled") } else { "disabled" }
    );

    for incoming in listener.incoming().flatten() {
        let Some(guard) = SlotGuard::try_acquire(&ACTIVE_HTTP_THREADS, MAX_HTTP_THREADS) else {
            let _ = incoming.set_write_timeout(Some(Duration::from_secs(2)));
            write_http(
                &incoming,
                "503 Service Unavailable",
                "application/json",
                "{\"error\":\"Server busy (HTTP worker limit reached)\"}",
            );
            continue;
        };
        let st = Arc::clone(&state);
        let c = cfg.clone();
        if thread::Builder::new()
            .name("t2m-http".to_string())
            .spawn(move || {
                let _guard = guard;
                handle_client(incoming, st, c);
            })
            .is_err()
        {
            eprintln!("[Thread2MQTT] Worker thread spawn rejected by OS");
        }
    }
}
