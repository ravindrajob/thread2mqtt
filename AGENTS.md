# AGENTS.md — AI & Vibe-Coding Guide for Thread2MQTT

This repository is designed to be **effortless for both humans and AI coding agents** (Cursor, Antigravity, Claude Code, Copilot).

## File Map (6 Files Total — Entire App!)
- `Cargo.toml` — Package metadata (`0` external crates — keep `[dependencies]` empty!).
- `src/config.rs` — Pure-Rust `configuration.yaml` loader (`defaults < YAML < env < CLI`), `${ENV_VAR}` expansion, fail-closed `read_only_mode: true`, sanitized YAML renderer.
- `src/lib.rs` — Core domain (`MeshSnapshot`, `ThreadNode`, `BorderRouterInfo`), OTBR REST & `ot-ctl` table parsers, SRP↔Matter correlation, MQTT 3.1.1 wire encoder + Home Assistant Auto-Discovery, Prometheus `/metrics`, synthetic 6-node demo mesh.
- `src/matter_ws.rs` — Pure-Rust RFC 6455 WebSocket client + exact 64-bit integer RFC 8259 JSON parser (`JsonVal::Uint(u64)`) speaking `python-matter-server` (`:5580/ws`): `get_nodes`, `ping_node`, `discover`, `check_node_update`, `commission_with_code`, `open_commissioning_window`, `interview_node`, `device_command` (`Identify`, `OnOff`).
- `src/diagnostics.rs` — 15 whitelisted read-only `ot-ctl` commands, MAC/IPv6 counter parsers, SRP `_matter._tcp` parser, RF energy scan parser, Matter QR (Base38) & Manual (11/21-digit + Verhoeff checksum) setup code decoder, Smart Mesh Health Advisor, `state.json` persistence.
- `src/main.rs` — Multi-threaded HTTP/1.1 + SSE server, background OTBR/Matter poller, MQTT publisher, optional `auth_token` constant-time Bearer/Cookie gate, `/device-images/` static handler, `/api/alerts`, `write_matter_reply` (converts Matter `error_code` to HTTP 502).
- `src/ui/index.html` — Single-file WindFront/Zigbee2MQTT-style responsive UI (inline CSS/JS/SVG, zero CDN, animated mesh SVG, FR/EN i18n, Dark/Light).
- `monitoring/` — Ready-to-import `grafana-dashboard.json` and `prometheus-alerts.yml`.

## Non-Negotiable Invariants
1. **Zero external crates** in `Cargo.toml`; **zero CDN links** in `src/ui/index.html`.
2. **Never break 64-bit JSON integers** (`compressed_fabric_id`, `node_id` must use `JsonVal::Uint(u64)`, never `f64`).
3. **Always validate real `python-matter-server` wire names:** `discover` (returns `long_discriminator`), `commission_with_code`, `open_commissioning_window`, `check_node_update`, `interview_node`, `ping_node`, `device_command`.
4. **Always enforce `read_only_mode`** on any mutating route (`HTTP 403`).
5. **Always run before opening a PR:**
   - `cargo test`
   - `pytest tests/`
   - `promtool check rules monitoring/prometheus-alerts.yml` (if alerts edited)
