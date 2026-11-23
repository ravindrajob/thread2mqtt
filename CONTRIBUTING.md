# Contributing to Thread2MQTT (Humans & AI-Assisted PRs Welcome!)

Thank you for helping make **Thread (OTBR)** and **Matter-over-Thread** networks effortless to inspect, diagnose, and run every day — accelerating Thread adoption across the smart-home community!

> **Open-Source Mission:** Thread2MQTT is an open-source **MIT-licensed** project written in pure Rust (`std`-only). Please submit only original MIT-compatible code and locally hosted / self-authored assets (never copy third-party copyrighted code or hotlink external sites).

---

## Core Engineering Rules (Read First)

1. **Zero External Rust Crates:** Keep `[dependencies]` empty in `Cargo.toml`. Pure Rust `std` guarantees `< 1 MB` static musl binaries, `< 1 MB` RAM, and zero supply-chain bloat.
2. **Zero External Web CDNs:** The UI (`src/ui/index.html`) is embedded via `include_str!` and must work 100 % offline (no Google Fonts, no unpkg/jsdelivr).
3. **Fail-Closed Production Safety:** `advanced.read_only_mode` defaults to `true`. Any mutating endpoint MUST return `HTTP 403` when `read_only_mode == true`.
4. **Zero Secret Leaks:** Never log, publish to MQTT, or commit `networkKey`, `pskc`, `auth_token`, real MAC addresses, or real Fabric IDs in fixtures/tests (use RFC-safe synthetic values like `020000000000000C` / `fd00:db8::/32`).

---

## Quick Local Test Loop (No Hardware Needed)

```bash
# Run all Rust unit tests (offline)
cargo test

# Run the built-in 6-node synthetic demo mesh
cargo run -- --demo --bind 127.0.0.1:8099

# Run Python contract & Zero-Trust safeguard tests
pytest tests/
```

---

## Easy High-Impact Contributions (Great for Vibe-Coding!)

### 1. Add a New Matter Cluster Expose (~15 lines in `src/matter_ws.rs`)
Look at `extract_matter_node()` in `src/matter_ws.rs`. Use `find_cluster_attr(attrs, <cluster_id>, <attr_id>)` (works across multi-endpoint devices!) and push a `MatterExpose`:
- Example targets: `DoorLock (0x0101 / 257)`, `Thermostat (0x0201 / 513)`, `WindowCovering (0x0102 / 258)`, `AirQuality (0x005B / 91)`, `ElectricalPowerMeasurement (0x0090 / 144)`.
- Add a unit test in `src/matter_ws.rs` verifying extraction.

### 2. Add a Device Image (`512x512` Transparent PNG)
Thread2MQTT resolves device visuals in 3 privacy-safe, self-hosted tiers (zero external CDN or hotlinking):
1. Per-device `icon:` in `configuration.yaml` (`device_images/my_sensor.png` or URL).
2. Local `<data_dir>/device_images/<vendor>_<product_slug>.png` (served by `/device-images/...`) or optional community `frontend.device_images_base_url`.
3. Automatic crisp inline SVG vector per device category (always works offline).

### 3. Add a Translation Language (`src/ui/index.html`)
Extend the `I18N` dictionary in `src/ui/index.html` (`fr`, `en`, `de`, `es`, `nl`, ...).

### 4. PR Checklist
- [ ] `cargo test` passes (`0` warnings if possible)
- [ ] `node --check` passes on `<script>` inside `src/ui/index.html`
- [ ] `pytest tests/` passes
- [ ] Zero real MACs, IPs, Fabric IDs, or keys in code or fixtures
