# Changelog

Iterative engineering log across real homelab Thread (OTBR) and `python-matter-server` testing.

## v0.5.0 - Ergonomic Sidebar Layout, Simple/Advanced Mode, QR Camera & Hardware Scan (`971 KB` bin / `936 KB` RSS)
- **Pedagogical UI tooltips (`ⓘ`), IPv6 OMR route check & `UNMATCHED` log filter:** Pure-CSS hover/focus tooltips on Thread/Matter concepts (RLOC16, IPv6 OMR, SRP, mDNS, Multi-Admin ECW, Dataset Vault), non-root `/proc/net/ipv6_route` OMR route verification badge on Dashboard & Devices, `UNMATCHED` correlation filter in live Logs, Zero-Trust CLI backup guide in Vault, and versioned [`docs/GUIDE.md`](docs/GUIDE.md) (Option A vs Option B, IPv6/mDNS, Multi-Admin Alexa/Google/Apple, Security & Backup).
- Structured left navigation (`Home`, `Dashboard`, `Devices`, `Groups`, `Radio & RF`, `Matter L7`, `OTA`, `Commissioning`, `Network`, `Logs`, `Dev Console`, `Settings`) with **Simple / Advanced** mode toggle.
- Added native browser `BarcodeDetector` QR camera scanner for `MT:...` Matter payloads with manual fallback.
- Added read-only `GET /api/hardware/scan` inspecting `/sys/class/bluetooth` (`hci*`), `/dev/serial/by-id`, and loopback OTBR/Matter ports to generate `--bluetooth-adapter` Compose snippets without `docker.sock` or shell calls.

## v0.4.0 - Protocol Precision, Error Propagation & Monitoring Pack
- **Fixed 64-bit integer truncation in JSON parser:** Matter `compressed_fabric_id` values exceed IEEE-754 `f64` 53-bit precision. Switched the custom RFC 8259 parser to exact `JsonVal::Uint(u64)` with dedicated regression tests.
- **Fixed silent Matter WS failures:** `python-matter-server` returns application errors inside JSON frames over an open WebSocket; added `write_matter_reply` to translate Matter `error_code` payloads into HTTP `502` responses.
- **Added Verhoeff checksum validation** (Matter Spec section 5.1.4.1) for 11-digit and 21-digit manual setup codes.
- Shipped ready-to-import `monitoring/grafana-dashboard.json` and `monitoring/prometheus-alerts.yml`.

## v0.3.0 - `configuration.yaml`, Fail-Closed Safety & Live Commissioning
- Added pure-Rust `configuration.yaml` loader (`defaults < YAML < env < CLI`) with `${ENV_VAR}` expansion and `advanced.read_only_mode: true` master safety lock.
- Implemented live `python-matter-server` commissioning (`discover`, `commission_with_code`, `open_commissioning_window` Multi-Admin ECW, `check_node_update` CSA DCL OTA, `interview_node`) gated behind both `read_only_mode: false` and `allow_commissioning: true`.
- Added 60-point in-memory RSSI sparklines and persistent `state.json` friendly names/groups.

## v0.2.0 - Live Matter WS & RF Diagnostics (`831 KB` bin / `836 KB` RSS)
- Implemented zero-crate RFC 6455 WebSocket client (`src/matter_ws.rs`) and automatic Thread SRP (`_matter._tcp`) to Matter L7 node correlation.
- Added 2.4 GHz RF energy scan, 802.15.4 MAC/IPv6 drop counters, 15 allowlisted read-only `ot-ctl` commands, and Mesh Health Advisor.

## v0.1.0 - Initial Pure-Rust Sidecar (`606 KB` bin / `536 KB` RSS)
- Built initial zero-dependency Rust `std` binary querying OTBR REST + `ot-ctl` tables, exposing an offline SVG mesh map, Home Assistant MQTT Auto-Discovery, and `/metrics` Prometheus exporter with secret masking on `networkKey`/`pskc`.
