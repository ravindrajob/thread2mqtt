# Contributing to Thread2MQTT

Contributions that improve Thread (OTBR) and Matter-over-Thread observability, protocol coverage, or UI ergonomics are welcome.

> **License:** Thread2MQTT is **MIT-licensed** and written in pure Rust (`std`-only). Please submit only original MIT-compatible code and locally hosted / self-authored assets.

## Core Engineering Rules

1. **Zero External Rust Crates:** Keep `[dependencies]` empty in `Cargo.toml`. Pure Rust `std` keeps static musl binaries under 1 MB, runtime RSS under 1 MB, and supply-chain surface at zero.
2. **Zero External Web CDNs:** `src/ui/index.html` is embedded via `include_str!` and must work 100% offline (no Google Fonts, no unpkg/jsdelivr).
3. **Fail-Closed Production Safety:** `advanced.read_only_mode` defaults to `true`. Any mutating endpoint must return `HTTP 403` when `read_only_mode == true`.
4. **Zero Secret Leaks:** Never log, publish to MQTT, or commit `networkKey`, `pskc`, `auth_token`, real MAC addresses, or real Fabric IDs in fixtures or tests (use synthetic locally administered MACs like `020000000000000C` and synthetic RFC 4193 ULA mesh-local prefixes like `fd00:db8::/64`).

## Local Test Loop (No Hardware Needed)

```bash
# Run all Rust unit tests (offline)
cargo test

# Run the built-in 6-node synthetic demo mesh
cargo run -- --demo --bind 127.0.0.1:8099

# Run Python contract & Zero-Trust safeguard tests
pytest tests/
```

## Good First Contributions

### 1. Add a Matter Cluster Expose (~15 lines in `src/matter_ws.rs`)
Inspect `extract_matter_node()` in `src/matter_ws.rs`, use `find_cluster_attr(attrs, <cluster_id>, <attr_id>)` (multi-endpoint safe), and push a `MatterExpose`:
- Useful targets: `DoorLock (0x0101 / 257)`, `Thermostat (0x0201 / 513)`, `WindowCovering (0x0102 / 258)`, `AirQuality (0x005B / 91)`, `ElectricalPowerMeasurement (0x0090 / 144)`.
- Add a unit test in `src/matter_ws.rs` verifying extraction.

### 2. Add a Device Image (`512x512` Transparent PNG)
Thread2MQTT resolves device visuals in 3 privacy-safe, self-hosted tiers (no external hotlinking):
1. Per-device `icon:` in `configuration.yaml` (`device_images/my_sensor.png` or URL).
2. Local `<data_dir>/device_images/<vendor>_<product_slug>.png` (served by `/device-images/...`) or optional `frontend.device_images_base_url`.
3. Automatic inline SVG vector per device category (always works offline).

### 3. Add a Translation Language (`src/ui/index.html`)
Extend the `I18N` dictionary in `src/ui/index.html` (`fr`, `en`, `de`, `es`, `nl`, ...).

## PR Checklist
- [ ] `cargo test` passes (`0` warnings if possible)
- [ ] `node --check` passes on `<script>` inside `src/ui/index.html`
- [ ] `pytest tests/` passes
- [ ] Zero real MACs, private IPs, Fabric IDs, or keys in code or fixtures
