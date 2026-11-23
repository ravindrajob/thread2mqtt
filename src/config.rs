//! Pure-Rust zero-dependency `configuration.yaml` loader & sanitized serializer
//! modeled after Zigbee2MQTT's `data/configuration.yaml` experience.
//!
//! Loading precedence (lowest -> highest):
//!   1. Safe fail-closed defaults (`read_only_mode: true`, `allow_commissioning: false`)
//!   2. `configuration.yaml` (supports `#` comments, 2-space nested blocks, `${ENV_VAR}` expansion)
//!   3. Environment variables (`OTBR_REST_URL`, `MATTER_WS_URL`, `THREAD2MQTT_*`, `MQTT_*`)
//!   4. CLI arguments (`--config`, `--demo`, `--bind`, `--otbr-url`, `--matter-ws`, `--mqtt-host`)

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::Path;

use crate::diagnostics::NodeMeta;
use crate::json_str;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub config_path: Option<String>,
    pub bind_addr: String,
    pub auth_token: Option<String>,
    pub default_theme: String,
    pub device_images_base_url: Option<String>,
    pub demo_mode: bool,
    pub read_only_mode: bool,
    pub otbr_url: Option<String>,
    pub otctl_cmd: Option<String>,
    pub matter_ws_url: Option<String>,
    pub allow_commissioning: bool,
    pub allow_interview: bool,
    pub allow_ota_check: bool,
    pub data_dir: Option<String>,
    pub zigbee_channel: Option<u8>,
    pub mqtt_enabled: bool,
    pub mqtt_host: Option<String>,
    pub mqtt_user: Option<String>,
    pub mqtt_pass: Option<String>,
    pub mqtt_base_topic: String,
    pub ha_discovery_enabled: bool,
    pub ha_discovery_prefix: String,
    pub poll_secs: u64,
    pub rssi_history_points: usize,
    pub yaml_devices: BTreeMap<String, NodeMeta>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            config_path: None,
            bind_addr: "127.0.0.1:8099".to_string(),
            auth_token: None,
            default_theme: "dark".to_string(),
            device_images_base_url: None,
            demo_mode: false,
            read_only_mode: true, // Fail-closed master safety lock
            otbr_url: None,
            otctl_cmd: None,
            matter_ws_url: None,
            allow_commissioning: false, // Explicit opt-in required in configuration.yaml
            allow_interview: true,
            allow_ota_check: true,
            data_dir: None,
            zigbee_channel: None,
            mqtt_enabled: false,
            mqtt_host: None,
            mqtt_user: None,
            mqtt_pass: None,
            mqtt_base_topic: "thread2mqtt".to_string(),
            ha_discovery_enabled: true,
            ha_discovery_prefix: "homeassistant".to_string(),
            poll_secs: 15,
            rssi_history_points: 60,
            yaml_devices: BTreeMap::new(),
        }
    }
}

/// Expands `${ENV_VAR}` references cleanly without executing shells.
pub fn expand_env_vars(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 2 < bytes.len() && bytes[i] == b'$' && bytes[i + 1] == b'{' {
            if let Some(rel_end) = input[i + 2..].find('}') {
                let var_name = &input[i + 2..i + 2 + rel_end];
                if !var_name.is_empty()
                    && var_name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_')
                {
                    if let Ok(val) = env::var(var_name) {
                        out.push_str(&val);
                    }
                    i += 3 + rel_end;
                    continue;
                }
            }
        }
        if let Some(ch) = input[i..].chars().next() {
            out.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }
    out
}

fn strip_yaml_comment(raw: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    for (idx, ch) in raw.char_indices() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '#' if !in_single && !in_double => {
                if idx == 0 || raw[..idx].ends_with(|c: char| c.is_whitespace()) {
                    return raw[..idx].trim_end();
                }
            }
            _ => {}
        }
    }
    raw.trim_end()
}

fn unquote_scalar(raw: &str) -> String {
    let t = raw.trim();
    if t.len() >= 2
        && ((t.starts_with('"') && t.ends_with('"')) || (t.starts_with('\'') && t.ends_with('\'')))
    {
        expand_env_vars(&t[1..t.len() - 1])
    } else {
        expand_env_vars(t)
    }
}

fn parse_bool(raw: &str) -> Option<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Some(true),
        "false" | "no" | "off" | "0" => Some(false),
        _ => None,
    }
}

/// Parses a Zigbee2MQTT-style `configuration.yaml` into an `AppConfig`.
pub fn parse_yaml_config(yaml: &str, cfg: &mut AppConfig) {
    let mut section = String::new();
    let mut current_device: Option<String> = None;

    for raw_line in yaml.lines() {
        let cleaned = strip_yaml_comment(raw_line);
        let trimmed = cleaned.trim();
        if trimmed.is_empty() {
            continue;
        }
        let indent = cleaned.chars().take_while(|c| *c == ' ').count();
        let Some((k_raw, v_raw)) = trimmed.split_once(':') else {
            continue;
        };
        let key = unquote_scalar(k_raw).trim().to_string();
        let val_trimmed = v_raw.trim();

        if indent == 0 {
            section = key.to_ascii_lowercase();
            current_device = None;
            continue;
        }

        if section == "devices" {
            if indent > 0 && val_trimmed.is_empty() {
                let norm = key.to_ascii_lowercase();
                if norm.len() == 16 && norm.chars().all(|c| c.is_ascii_hexdigit()) {
                    current_device = Some(norm);
                } else {
                    current_device = None;
                }
                continue;
            }
            if let Some(dev_ext) = &current_device {
                let v = unquote_scalar(val_trimmed);
                if v.is_empty() {
                    continue;
                }
                let entry = cfg.yaml_devices.entry(dev_ext.clone()).or_default();
                match key.as_str() {
                    "friendly_name" => entry.friendly_name = Some(v),
                    "group" | "room" => entry.group = Some(v),
                    "description" => entry.description = Some(v),
                    "icon" | "image" => entry.icon = Some(v),
                    _ => {}
                }
            }
            continue;
        }

        let v = unquote_scalar(val_trimmed);
        let opt_non_empty = if v.trim().is_empty() || v == "null" || v == "~" {
            None
        } else {
            Some(v.clone())
        };

        match (section.as_str(), key.as_str()) {
            ("frontend", "bind") => {
                if let Some(b) = opt_non_empty {
                    cfg.bind_addr = b;
                }
            }
            ("frontend", "auth_token") => cfg.auth_token = opt_non_empty,
            ("frontend", "default_theme") => {
                if v == "light" || v == "dark" {
                    cfg.default_theme = v;
                }
            }
            ("frontend", "device_images_base_url") => cfg.device_images_base_url = opt_non_empty,
            ("thread", "otbr_rest_url") => cfg.otbr_url = opt_non_empty,
            ("thread", "otctl_cmd") => cfg.otctl_cmd = opt_non_empty,
            ("thread", "poll_interval_secs") => {
                if let Ok(n) = v.parse::<u64>() {
                    cfg.poll_secs = n.clamp(5, 300);
                }
            }
            ("thread", "zigbee_channel") => {
                cfg.zigbee_channel = v.parse::<u8>().ok().filter(|c| (11..=26).contains(c));
            }
            ("matter", "ws_url") => cfg.matter_ws_url = opt_non_empty,
            ("matter", "allow_commissioning") => {
                if let Some(b) = parse_bool(&v) {
                    cfg.allow_commissioning = b;
                }
            }
            ("matter", "allow_interview") => {
                if let Some(b) = parse_bool(&v) {
                    cfg.allow_interview = b;
                }
            }
            ("matter", "allow_ota_check") => {
                if let Some(b) = parse_bool(&v) {
                    cfg.allow_ota_check = b;
                }
            }
            ("mqtt", "enabled") => {
                if let Some(b) = parse_bool(&v) {
                    cfg.mqtt_enabled = b;
                }
            }
            ("mqtt", "server") => cfg.mqtt_host = opt_non_empty,
            ("mqtt", "user") => cfg.mqtt_user = opt_non_empty,
            ("mqtt", "password") => cfg.mqtt_pass = opt_non_empty,
            ("mqtt", "base_topic") => {
                if let Some(t) = opt_non_empty {
                    cfg.mqtt_base_topic = t;
                }
            }
            ("mqtt", "homeassistant_discovery") => {
                if let Some(b) = parse_bool(&v) {
                    cfg.ha_discovery_enabled = b;
                }
            }
            ("mqtt", "discovery_prefix") => {
                if let Some(p) = opt_non_empty {
                    cfg.ha_discovery_prefix = p;
                }
            }
            ("advanced", "read_only_mode") => {
                if let Some(b) = parse_bool(&v) {
                    cfg.read_only_mode = b;
                }
            }
            ("advanced", "data_dir") => cfg.data_dir = opt_non_empty,
            ("advanced", "demo_mode") => {
                if let Some(b) = parse_bool(&v) {
                    cfg.demo_mode = b;
                }
            }
            ("advanced", "rssi_history_points") => {
                if let Ok(n) = v.parse::<usize>() {
                    cfg.rssi_history_points = n.clamp(10, 240);
                }
            }
            _ => {}
        }
    }
}

impl AppConfig {
    /// Loads configuration with precedence: defaults < configuration.yaml < env < CLI args.
    pub fn load() -> Self {
        let args: Vec<String> = env::args().collect();
        let mut cfg = AppConfig::default();

        // Discover optional configuration.yaml path
        let mut yaml_path = env::var("THREAD2MQTT_CONFIG")
            .ok()
            .filter(|s| !s.trim().is_empty());
        let mut i = 1;
        while i < args.len() {
            if args[i] == "--config" && i + 1 < args.len() {
                yaml_path = Some(args[i + 1].clone());
                i += 1;
            }
            i += 1;
        }
        if yaml_path.is_none() {
            let candidates = [
                env::var("THREAD2MQTT_DATA_DIR")
                    .ok()
                    .map(|d| format!("{}/configuration.yaml", d.trim_end_matches('/'))),
                Some("./configuration.yaml".to_string()),
                Some("/data/configuration.yaml".to_string()),
            ];
            for cand in candidates.into_iter().flatten() {
                if Path::new(&cand).is_file() {
                    yaml_path = Some(cand);
                    break;
                }
            }
        }
        if let Some(path) = &yaml_path {
            match fs::read_to_string(path) {
                Ok(raw) => {
                    parse_yaml_config(&raw, &mut cfg);
                    cfg.config_path = Some(path.clone());
                }
                Err(e) => {
                    eprintln!("[Thread2MQTT] WARN: unable to read config '{}': {}", path, e);
                }
            }
        }

        // Environment variable overrides
        if let Ok(v) = env::var("THREAD2MQTT_DEMO") {
            if let Some(b) = parse_bool(&v) {
                cfg.demo_mode = b;
            }
        }
        if let Ok(v) = env::var("THREAD2MQTT_READ_ONLY") {
            if let Some(b) = parse_bool(&v) {
                cfg.read_only_mode = b;
            }
        }
        if let Ok(v) = env::var("THREAD2MQTT_ALLOW_COMMISSIONING") {
            if let Some(b) = parse_bool(&v) {
                cfg.allow_commissioning = b;
            }
        }
        if let Ok(v) = env::var("THREAD2MQTT_BIND") {
            if !v.trim().is_empty() {
                cfg.bind_addr = v;
            }
        }
        if let Ok(v) = env::var("THREAD2MQTT_AUTH_TOKEN") {
            if !v.trim().is_empty() {
                cfg.auth_token = Some(v);
            }
        }
        if let Ok(v) = env::var("THREAD2MQTT_DEVICE_IMAGES_URL") {
            if !v.trim().is_empty() {
                cfg.device_images_base_url = Some(v);
            }
        }
        if let Ok(v) = env::var("OTBR_REST_URL") {
            if !v.trim().is_empty() {
                cfg.otbr_url = Some(v);
            }
        }
        if let Ok(v) = env::var("OTCTL_CMD") {
            if !v.trim().is_empty() {
                cfg.otctl_cmd = Some(v);
            }
        }
        if let Ok(v) = env::var("MATTER_WS_URL") {
            if !v.trim().is_empty() {
                cfg.matter_ws_url = Some(v);
            }
        }
        if let Ok(v) = env::var("THREAD2MQTT_DATA_DIR") {
            if !v.trim().is_empty() {
                cfg.data_dir = Some(v);
            }
        }
        if let Ok(v) = env::var("ZIGBEE_CHANNEL") {
            if let Some(c) = v.parse::<u8>().ok().filter(|c| (11..=26).contains(c)) {
                cfg.zigbee_channel = Some(c);
            }
        }
        if let Ok(v) = env::var("MQTT_HOST") {
            if !v.trim().is_empty() {
                cfg.mqtt_host = Some(v);
                cfg.mqtt_enabled = true;
            }
        }
        if let Ok(v) = env::var("MQTT_USER") {
            if !v.trim().is_empty() {
                cfg.mqtt_user = Some(v);
            }
        }
        if let Ok(v) = env::var("MQTT_PASS") {
            if !v.trim().is_empty() {
                cfg.mqtt_pass = Some(v);
            }
        }
        if let Ok(v) = env::var("MQTT_BASE_TOPIC") {
            if !v.trim().is_empty() {
                cfg.mqtt_base_topic = v;
            }
        }
        if let Ok(v) = env::var("HA_DISCOVERY_PREFIX") {
            if !v.trim().is_empty() {
                cfg.ha_discovery_prefix = v;
            }
        }
        if let Ok(v) = env::var("THREAD2MQTT_POLL_SECS") {
            if let Ok(n) = v.parse::<u64>() {
                cfg.poll_secs = n.clamp(5, 300);
            }
        }

        // CLI flag overrides
        let mut idx = 1;
        while idx < args.len() {
            match args[idx].as_str() {
                "--demo" => cfg.demo_mode = true,
                "--read-only" => cfg.read_only_mode = true,
                "--allow-commissioning" => {
                    cfg.read_only_mode = false;
                    cfg.allow_commissioning = true;
                }
                "--bind" if idx + 1 < args.len() => {
                    cfg.bind_addr = args[idx + 1].clone();
                    idx += 1;
                }
                "--otbr-url" if idx + 1 < args.len() => {
                    cfg.otbr_url = Some(args[idx + 1].clone());
                    idx += 1;
                }
                "--matter-ws" if idx + 1 < args.len() => {
                    cfg.matter_ws_url = Some(args[idx + 1].clone());
                    idx += 1;
                }
                "--mqtt-host" if idx + 1 < args.len() => {
                    cfg.mqtt_host = Some(args[idx + 1].clone());
                    cfg.mqtt_enabled = true;
                    idx += 1;
                }
                "--help" | "-h" => {
                    println!(
                        "Thread2MQTT v{} — Rust Thread/OTBR/Matter to MQTT Bridge & Zigbee2MQTT-Style UI\n\
                         Usage: thread2mqtt [--config configuration.yaml] [--demo] [--bind 127.0.0.1:8099] [--otbr-url URL] [--matter-ws ws://HOST:5580/ws] [--mqtt-host HOST:1883]\n\
                         Safety: read_only_mode defaults to true. Enable commissioning explicitly in configuration.yaml.",
                        env!("CARGO_PKG_VERSION")
                    );
                    std::process::exit(0);
                }
                _ => {}
            }
            idx += 1;
        }

        if cfg.otbr_url.is_none() && cfg.otctl_cmd.is_none() {
            cfg.demo_mode = true;
        }
        cfg
    }

    /// True only when both master `read_only_mode` is disabled AND `matter.allow_commissioning` is enabled.
    pub fn can_commission(&self) -> bool {
        !self.read_only_mode && self.allow_commissioning
    }

    pub fn can_interview(&self) -> bool {
        !self.read_only_mode && self.allow_interview
    }

    /// Renders a clean, secret-free `configuration.yaml` representation for the Web UI & downloads.
    pub fn to_sanitized_yaml(&self) -> String {
        let mut out = String::new();
        out.push_str("# Thread2MQTT — Active Configuration (Secrets Masked)\n");
        out.push_str("frontend:\n");
        out.push_str(&format!("  bind: \"{}\"\n", self.bind_addr));
        out.push_str(&format!("  default_theme: \"{}\"\n", self.default_theme));
        if let Some(img_url) = &self.device_images_base_url {
            out.push_str(&format!("  device_images_base_url: \"{}\"\n", img_url));
        } else {
            out.push_str("  # device_images_base_url: \"\"   # Local SVG + /data/device_images/ by default (Zero-CDN)\n");
        }
        if self.auth_token.is_some() {
            out.push_str("  auth_token: \"********\"\n");
        } else {
            out.push_str("  # auth_token: \"\"   # Optional Bearer token\n");
        }
        out.push_str("\nthread:\n");
        out.push_str(&format!(
            "  otbr_rest_url: \"{}\"\n",
            self.otbr_url.as_deref().unwrap_or("")
        ));
        out.push_str(&format!(
            "  otctl_cmd: \"{}\"\n",
            self.otctl_cmd.as_deref().unwrap_or("")
        ));
        out.push_str(&format!("  poll_interval_secs: {}\n", self.poll_secs));
        if let Some(z) = self.zigbee_channel {
            out.push_str(&format!("  zigbee_channel: {}\n", z));
        }
        out.push_str("\nmatter:\n");
        out.push_str(&format!(
            "  ws_url: \"{}\"\n",
            self.matter_ws_url.as_deref().unwrap_or("")
        ));
        out.push_str(&format!(
            "  allow_commissioning: {}\n",
            self.allow_commissioning
        ));
        out.push_str(&format!("  allow_interview: {}\n", self.allow_interview));
        out.push_str(&format!("  allow_ota_check: {}\n", self.allow_ota_check));
        out.push_str("\nmqtt:\n");
        out.push_str(&format!("  enabled: {}\n", self.mqtt_enabled));
        out.push_str(&format!(
            "  server: \"{}\"\n",
            self.mqtt_host.as_deref().unwrap_or("")
        ));
        if let Some(u) = &self.mqtt_user {
            out.push_str(&format!("  user: \"{}\"\n", u));
        }
        if self.mqtt_pass.is_some() {
            out.push_str("  password: \"********\"\n");
        }
        out.push_str(&format!("  base_topic: \"{}\"\n", self.mqtt_base_topic));
        out.push_str(&format!(
            "  homeassistant_discovery: {}\n",
            self.ha_discovery_enabled
        ));
        out.push_str(&format!(
            "  discovery_prefix: \"{}\"\n",
            self.ha_discovery_prefix
        ));
        out.push_str("\nadvanced:\n");
        out.push_str(&format!("  read_only_mode: {}\n", self.read_only_mode));
        out.push_str(&format!("  demo_mode: {}\n", self.demo_mode));
        out.push_str(&format!(
            "  data_dir: \"{}\"\n",
            self.data_dir.as_deref().unwrap_or("")
        ));
        out.push_str(&format!(
            "  rssi_history_points: {}\n",
            self.rssi_history_points
        ));
        out
    }

    pub fn to_public_json(&self) -> String {
        format!(
            "{{\"version\":{},\"config_path\":{},\"read_only_mode\":{},\"can_commission\":{},\"can_interview\":{},\"allow_commissioning\":{},\"allow_interview\":{},\"allow_ota_check\":{},\"matter_configured\":{},\"otctl_configured\":{},\"mqtt_enabled\":{},\"ha_discovery_enabled\":{},\"auth_required\":{},\"default_theme\":{},\"device_images_base_url\":{},\"poll_secs\":{},\"zigbee_channel\":{},\"mqtt_base_topic\":{},\"ha_discovery_prefix\":{},\"sanitized_yaml\":{}}}",
            json_str(env!("CARGO_PKG_VERSION")),
            self.config_path
                .as_deref()
                .map(json_str)
                .unwrap_or_else(|| "null".to_string()),
            self.read_only_mode,
            self.can_commission(),
            self.can_interview(),
            self.allow_commissioning,
            self.allow_interview,
            self.allow_ota_check,
            self.matter_ws_url.is_some(),
            self.otctl_cmd.is_some(),
            self.mqtt_enabled,
            self.ha_discovery_enabled,
            self.auth_token.is_some(),
            json_str(&self.default_theme),
            self.device_images_base_url
                .as_deref()
                .map(json_str)
                .unwrap_or_else(|| "null".to_string()),
            self.poll_secs,
            self.zigbee_channel
                .map(|z| z.to_string())
                .unwrap_or_else(|| "null".to_string()),
            json_str(&self.mqtt_base_topic),
            json_str(&self.ha_discovery_prefix),
            json_str(&self.to_sanitized_yaml())
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_yaml_config_and_fail_closed_defaults() {
        let mut cfg = AppConfig::default();
        assert!(cfg.read_only_mode);
        assert!(!cfg.can_commission());

        let yaml = r#"
# Example configuration.yaml
frontend:
  bind: "127.0.0.1:8099"
  auth_token: "super-secret-token"
  default_theme: "light"

thread:
  otbr_rest_url: "http://127.0.0.1:8081" # inline comment
  otctl_cmd: "ot-ctl"
  poll_interval_secs: 20
  zigbee_channel: 11

matter:
  ws_url: "ws://127.0.0.1:5580/ws"
  allow_commissioning: true
  allow_interview: true

mqtt:
  enabled: true
  server: "127.0.0.1:1883"
  user: "thread"
  password: "secret-mqtt-password"
  base_topic: "thread2mqtt"

advanced:
  read_only_mode: false
  data_dir: "/data"

devices:
  "020000000000000c":
    friendly_name: "Smoke Hallway"
    group: "Safety"
    description: "Upper floor"
"#;
        parse_yaml_config(yaml, &mut cfg);
        assert!(!cfg.read_only_mode);
        assert!(cfg.can_commission());
        assert_eq!(cfg.zigbee_channel, Some(11));
        assert_eq!(cfg.poll_secs, 20);
        assert!(cfg.mqtt_enabled);
        assert_eq!(cfg.mqtt_host.as_deref(), Some("127.0.0.1:1883"));
        let dev = cfg.yaml_devices.get("020000000000000c").expect("device parsed");
        assert_eq!(dev.friendly_name.as_deref(), Some("Smoke Hallway"));
        assert_eq!(dev.group.as_deref(), Some("Safety"));

        // Sanitized YAML must NEVER leak secrets
        let rendered = cfg.to_sanitized_yaml();
        assert!(!rendered.contains("super-secret-token"));
        assert!(!rendered.contains("secret-mqtt-password"));
        assert!(rendered.contains("auth_token: \"********\""));
        assert!(rendered.contains("password: \"********\""));
    }

    #[test]
    fn test_read_only_mode_overrides_allow_commissioning() {
        let mut cfg = AppConfig::default();
        parse_yaml_config(
            "matter:\n  allow_commissioning: true\nadvanced:\n  read_only_mode: true\n",
            &mut cfg,
        );
        assert!(cfg.allow_commissioning);
        assert!(cfg.read_only_mode);
        assert!(!cfg.can_commission());
    }
}
