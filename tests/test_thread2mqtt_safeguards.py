"""Safeguard & contract tests for the open-source Rust Thread2MQTT module."""
from pathlib import Path
import re

MODULE_DIR = Path(__file__).resolve().parent.parent


def test_thread2mqtt_zero_external_crates_and_structure():
    cargo = (MODULE_DIR / "Cargo.toml").read_text(encoding="utf-8")
    assert 'name = "thread2mqtt"' in cargo
    assert 'edition = "2021"' in cargo
    # Pure Rust std-only policy: no third-party crate lines under [dependencies]
    deps_block = cargo.split("[dependencies]")[1].split("[profile.")[0]
    active_deps = [
        line.strip()
        for line in deps_block.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    assert active_deps == [], f"Unexpected external crates in Cargo.toml: {active_deps}"
    assert (MODULE_DIR / "src/lib.rs").is_file()
    assert (MODULE_DIR / "src/config.rs").is_file()
    assert (MODULE_DIR / "src/main.rs").is_file()
    assert (MODULE_DIR / "src/matter_ws.rs").is_file()
    assert (MODULE_DIR / "src/diagnostics.rs").is_file()
    assert (MODULE_DIR / "src/ui/index.html").is_file()
    assert (MODULE_DIR / "configuration.yaml.example").is_file()
    assert (MODULE_DIR / "Dockerfile").is_file()
    assert (MODULE_DIR / "docker-compose.yml").is_file()


def test_thread2mqtt_zero_trust_secrets_and_container_hardening():
    lib_rs = (MODULE_DIR / "src/lib.rs").read_text(encoding="utf-8")
    diag_rs = (MODULE_DIR / "src/diagnostics.rs").read_text(encoding="utf-8")
    mws_rs = (MODULE_DIR / "src/matter_ws.rs").read_text(encoding="utf-8")
    compose = (MODULE_DIR / "docker-compose.yml").read_text(encoding="utf-8")
    ui_html = (MODULE_DIR / "src/ui/index.html").read_text(encoding="utf-8")

    # Zero-secret MQTT redaction, mesh/RF diagnostics & HA auto-discovery invariants
    assert "pub fn sanitize_mqtt_payload(" in lib_rs
    assert "pub fn mask_secret_hex(" in lib_rs
    assert "pub fn correlate_srp_and_matter(" in lib_rs
    assert "pub fn build_ha_discovery_payloads(" in lib_rs
    assert "pub fn render_prometheus_metrics(" in lib_rs
    assert "pub fn decode_matter_setup_code(" in diag_rs
    assert "pub fn is_whitelisted_otctl(" in diag_rs
    assert "pub fn analyze_mesh_health(" in diag_rs
    assert "pub fn fetch_matter_server_snapshot(" in mws_rs
    assert "spectrumSvg" in ui_html

    # Hardened container invariants
    assert "read_only: true" in compose
    assert "no-new-privileges:true" in compose
    assert "cap_drop:" in compose
    assert "mem_limit:" in compose

    # Zero external CDN links in embedded Web UI
    assert not re.search(r"https?://(?:cdn\.|unpkg\.|cdnjs\.|fonts\.googleapis)", ui_html)

    # Anti-hallucination & protocol accuracy invariants (audited 2026-11-22)
    main_rs = (MODULE_DIR / "src/main.rs").read_text(encoding="utf-8")
    readme = (MODULE_DIR / "README.md").read_text(encoding="utf-8")
    cargo = (MODULE_DIR / "Cargo.toml").read_text(encoding="utf-8")
    assert 'version = "0.5.0"' in cargo
    assert "pub fn scan_local_hardware(" in lib_rs
    assert "/api/hardware/scan" in main_rs and "api/hardware/scan" in ui_html
    assert "adv-mode" in ui_html and "BarcodeDetector" in ui_html
    assert "Uint(u64)" in mws_rs  # Exact 64-bit JSON integers (no f64 fabric_id truncation)
    assert "fn verhoeff_valid(" in diag_rs  # Matter Spec §5.1.4.1 manual code checksum
    assert "fn write_matter_reply(" in main_rs  # Propagates Matter WS error_code as HTTP 502
    assert "long_discriminator" in ui_html and "long_discriminator" in main_rs
    assert "mesh-flow" in ui_html  # Animated mesh telemetry links
    assert "/device-images/" in main_rs and "/api/alerts" in main_rs and "/api/matter-command" in main_rs
    assert (MODULE_DIR / "monitoring/grafana-dashboard.json").is_file()
    assert (MODULE_DIR / "monitoring/prometheus-alerts.yml").is_file()
    assert (MODULE_DIR / "CONTRIBUTING.md").is_file()
    assert (MODULE_DIR / "AGENTS.md").is_file()
    assert "discover_commissionable_nodes" not in readme
    assert "/api/permit-join" not in main_rs
    assert "allow_remove_node" not in main_rs and "allow_remove_node" not in ui_html
    assert "pub fn ha_rename_matter_device(" in mws_rs
    assert "pub fn matter_set_node_label(" in mws_rs
    assert "_last_seen/config" in lib_rs and '"\\"pairing_code\\""' in lib_rs
    assert "renameOverlay" in ui_html and "rnSyncHa" in ui_html

    # Karpathy Multi-IA Council security & SRE hardening invariants (Fable 5.2 + Astra + AGY)
    dockerfile = (MODULE_DIR / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY assets/devices ./assets/devices" in dockerfile
    assert "strip target/release/thread2mqtt" in dockerfile
    assert "mem_limit: 64m" in compose
    assert "pub fn tcp_connect_timeout(" in lib_rs and "tcp_connect_timeout(" in mws_rs
    assert "has_pairing_code" in lib_rs and "has_pairing_code" in ui_html
    assert "MAX_HTTP_THREADS" in main_rs and "MAX_SSE_CONNS" in main_rs
    assert "Content-Security-Policy:" in main_rs
    assert "/api/pairing-code/reveal" in main_rs and "api/pairing-code/reveal" in ui_html
    assert "STATE_FILE_LOCK" in diag_rs and "sync_all()" in diag_rs
    assert "quickRename('${esc(n.ext_address)}','${esc(n.friendly_name)}')" not in ui_html
