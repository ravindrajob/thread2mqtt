//! Thread2MQTT v0.5 Daemon — Single static pure-Rust `std` binary serving:
//!  - Zigbee2MQTT/WindFront-style embedded Web UI (`/` — zero external CDN, HA Ingress ready)
//!  - Live OpenThread Border Router (REST + `ot-ctl`) + Live `python-matter-server` WebSocket correlation
//!  - Automatic SRP (`_matter._tcp`) L2/L3 <-> L7 binding + MAC/IPv6 RF Diagnostics + Health Advisor
//!  - Matter QR/Manual Setup Code Decoder (Base38 + Verhoeff) + Opt-In Commissioning / ECW / OTA / mDNS
//!  - Zigbee2MQTT-style `configuration.yaml` (fail-closed `read_only_mode: true`) + Persistent `state.json`
//!  - MQTT 3.1.1 Home Assistant Auto-Discovery + Live SSE Logs (`/api/events`) + Prometheus (`/metrics`)

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use thread2mqtt::config::AppConfig;
use thread2mqtt::diagnostics::{
    analyze_mesh_health, compute_node_health_score, decode_matter_setup_code, is_whitelisted_otctl,
    load_node_meta_store, parse_otctl_energy_scan, parse_otctl_ip_counters,
    parse_otctl_mac_counters, parse_otctl_srp_services, save_node_meta_store, IpCounters,
    MacCounters, NodeMeta,
};
use thread2mqtt::matter_ws::{
    fetch_matter_server_snapshot, matter_check_node_update, matter_commission_with_code,
    matter_discover_commissionable, matter_identify_node, matter_interview_node,
    matter_open_commissioning_window, matter_ping_node, matter_set_onoff, parse_json,
};
use thread2mqtt::{
    apply_otctl_neighbor_table, build_demo_snapshot, build_ha_discovery_payloads,
    correlate_srp_and_matter, fetch_http_json, json_get_i64, json_get_str, json_str, now_epoch_s,
    parse_otbr_dataset_json, parse_otbr_node_json, parse_otctl_child_table,
    parse_otctl_router_table, rebuild_mesh_links, render_prometheus_metrics,
    sanitize_friendly_name, sanitize_mqtt_payload, sanitize_topic_slug, scan_local_hardware,
    BorderRouterInfo, MeshSnapshot, MqttPublisher, ThreadNode, ThreadRole,
};

const EMBEDDED_UI_HTML: &str = include_str!("ui/index.html");

fn ct_eq(a: &str, b: &str) -> bool {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    if ab.len() != bb.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in ab.iter().zip(bb.iter()) {
        diff |= x ^ y;
    }
    diff == 0
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
        for n in &mut nodes {
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
        snap.br = br;
        snap.br_ipaddrs = br_ipaddrs;
        snap.br_omr_prefix = br_omr_prefix;
        snap.mac_counters = mac_counters;
        snap.ip_counters = ip_counters;
        snap.srp_services = srp_services;
        snap.mesh_health_score = mesh_health;
        snap.health_issues = health_issues;
        snap.nodes = nodes;
        snap.links = links;

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
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        status,
        content_type,
        body.len()
    );
    let _ = stream.write_all(hdr.as_bytes());
    let _ = stream.write_all(body.as_bytes());
}

fn write_http_bytes(mut stream: &TcpStream, status: &str, content_type: &str, body: &[u8]) {
    let hdr = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nCache-Control: public, max-age=3600\r\nConnection: close\r\n\r\n",
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
    let Some(dir) = cfg.data_dir.as_deref() else {
        write_http(stream, "404 Not Found", "application/json", "{\"error\":\"data_dir not configured\"}");
        return;
    };
    let path = Path::new(dir).join("device_images").join(filename);
    match fs::read(&path) {
        Ok(bytes) if bytes.len() <= 2 * 1024 * 1024 => write_http_bytes(stream, "200 OK", mime, &bytes),
        _ => write_http(stream, "404 Not Found", "application/json", "{\"error\":\"Device image not found\"}"),
    }
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
    let hdr = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n";
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
        let _ = stream.write_all(b": keepalive\n\n");
        let _ = stream.flush();
        thread::sleep(Duration::from_secs(2));
    }
}

fn handle_client(stream: TcpStream, state: Arc<Mutex<MeshSnapshot>>, cfg: AppConfig) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(6)));
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    let mut req_line = String::new();
    if reader.read_line(&mut req_line).is_err() {
        return;
    }
    let parts: Vec<&str> = req_line.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }
    let method = parts[0];
    let path = parts[1].split('?').next().unwrap_or("/");

    let mut content_len: usize = 0;
    let mut provided_token: Option<String> = None;
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" || h == "\n" {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            let val = v.trim();
            if k.eq_ignore_ascii_case("content-length") {
                content_len = val.parse::<usize>().unwrap_or(0).min(32768);
            } else if k.eq_ignore_ascii_case("authorization") {
                if let Some(bearer) = val.strip_prefix("Bearer ").or_else(|| val.strip_prefix("bearer ")) {
                    provided_token = Some(bearer.trim().to_string());
                }
            } else if k.eq_ignore_ascii_case("x-auth-token") {
                provided_token = Some(val.to_string());
            } else if k.eq_ignore_ascii_case("cookie") && provided_token.is_none() {
                for kv in val.split(';') {
                    if let Some(tok) = kv.trim().strip_prefix("t2m_auth=") {
                        provided_token = Some(tok.trim().to_string());
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

    // Optional frontend.auth_token enforcement (Zero-Trust for exposed LAN deployments)
    let is_public_shell = matches!(
        (method, path),
        ("GET", "/") | ("GET", "/index.html") | ("HEAD", "/") | ("HEAD", "/index.html") | ("GET", "/health") | ("HEAD", "/health")
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
        ("POST", "/api/rename") | ("POST", "/api/node-meta") => {
            let ext = json_get_str(&body, "ext_address").map(|s| s.to_ascii_lowercase());
            let name = json_get_str(&body, "friendly_name").and_then(|s| sanitize_friendly_name(&s));
            let has_group = body.contains("\"group\"");
            let has_desc = body.contains("\"description\"");
            let has_icon = body.contains("\"icon\"");
            let group = json_get_str(&body, "group").and_then(|s| sanitize_friendly_name(&s));
            let desc = json_get_str(&body, "description").and_then(|s| sanitize_friendly_name(&s));
            let icon = json_get_str(&body, "icon")
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty() && s.len() <= 256 && !s.contains("..") && !s.to_ascii_lowercase().starts_with("javascript:"));
            match ext {
                Some(e) if e.len() == 16 && e.chars().all(|c| c.is_ascii_hexdigit()) && (name.is_some() || has_group || has_desc || has_icon) => {
                    let mut saved_store: Option<BTreeMap<String, NodeMeta>> = None;
                    if let Ok(mut s) = state.lock() {
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
                        }
                        s.push_event(
                            "INFO",
                            "HTTP",
                            &format!("Updated metadata for node {}", e),
                            &format!(
                                "{{\"ext_address\":{},\"friendly_name\":{},\"group\":{}}}",
                                json_str(&e),
                                name.as_deref().map(json_str).unwrap_or_else(|| "null".into()),
                                group.as_deref().map(json_str).unwrap_or_else(|| "null".into())
                            ),
                        );
                        saved_store = Some(s.node_meta.clone());
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
                    write_http(
                        &stream,
                        "200 OK",
                        "application/json",
                        &format!("{{\"status\":\"ok\",\"persisted\":{}}}", persisted),
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
                    s.updated_at_s = now_epoch_s();
                    for (idx, n) in s.nodes.iter_mut().enumerate() {
                        if idx > 0 {
                            let jitter = ((tick as i32 + idx as i32) % 3) - 1;
                            n.last_rssi_dbm = (n.avg_rssi_dbm + jitter).clamp(-96, -35);
                            n.age_sec = ((tick * bg_cfg.poll_secs) as u32 % 45) + 2;
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
        let st = Arc::clone(&state);
        let c = cfg.clone();
        thread::spawn(move || handle_client(incoming, st, c));
    }
}
