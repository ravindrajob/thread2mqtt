# AGENTS.md - Architecture & Contributor Notes

Concise technical map and invariants for developers and automated review tools working on Thread2MQTT.

## File Map (6 Core Source Files)

- `Cargo.toml`: Package metadata (`0` external crates - keep `[dependencies]` empty).
- `src/config.rs`: Pure-Rust `configuration.yaml` loader (`defaults < YAML < env < CLI`), `${ENV_VAR}` expansion, fail-closed `read_only_mode: true`, sanitized YAML renderer.
- `src/lib.rs`: Core domain (`MeshSnapshot`, `ThreadNode`, `BorderRouterInfo`), OTBR REST and `ot-ctl` table parsers, SRP-to-Matter correlation, MQTT 3.1.1 wire encoder + Home Assistant Auto-Discovery, Prometheus `/metrics`, synthetic 6-node demo mesh, local hardware scanner.
- `src/matter_ws.rs`: Pure-Rust RFC 6455 WebSocket client and exact 64-bit integer RFC 8259 JSON parser (`JsonVal::Uint(u64)`) speaking `python-matter-server` (`:5580/ws`): `get_nodes`, `ping_node`, `discover`, `check_node_update`, `commission_with_code`, `open_commissioning_window`, `interview_node`, `device_command` (`Identify`, `OnOff`).
- `src/diagnostics.rs`: 15 allowlisted read-only `ot-ctl` commands, MAC/IPv6 counter parsers, SRP `_matter._tcp` parser, RF energy scan parser, Matter QR (Base38) and Manual (11/21-digit + Verhoeff checksum) setup code decoder, mesh health advisor, `state.json` persistence.
- `src/main.rs`: Multi-threaded HTTP/1.1 + SSE server, background OTBR/Matter poller, MQTT publisher, optional `auth_token` constant-time Bearer/Cookie gate, `/device-images/` static handler, `/api/alerts`, `write_matter_reply` (maps Matter `error_code` to HTTP 502).
- `src/ui/index.html`: Single-file responsive Web UI (inline CSS/JS/SVG, zero CDN, animated mesh SVG, 2.4 GHz RF spectrum, FR/EN i18n, Dark/Light).
- `monitoring/`: Ready-to-import `grafana-dashboard.json` and `prometheus-alerts.yml`.

## Non-Negotiable Invariants

1. **Zero external crates** in `Cargo.toml`; **zero CDN links** in `src/ui/index.html`.
2. **Exact 64-bit JSON integers:** `compressed_fabric_id` and `node_id` must use `JsonVal::Uint(u64)`, never `f64`.
3. **Exact `python-matter-server` wire names:** `discover` (returns `long_discriminator`), `commission_with_code`, `open_commissioning_window`, `check_node_update`, `interview_node`, `ping_node`, `device_command`.
4. **Fail-closed mutations:** Always enforce `read_only_mode` on mutating routes (`HTTP 403`).
5. **Pre-PR verification:**
   - `cargo test`
   - `pytest tests/`
   - `promtool check rules monitoring/prometheus-alerts.yml` (when editing alerts)
