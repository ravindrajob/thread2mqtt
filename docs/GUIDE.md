# Thread2MQTT — Technical Guide (Architecture, IPv6/mDNS, Security & Backup)

This guide is versioned alongside the code so it always matches the active release.

---

## 1. OTBR Deployment Modes (Option A vs Option B)

| Mode | Architecture | Compatibility with `thread2mqtt` | Notes |
| :--- | :--- | :--- | :--- |
| **Option A (Recommended)** | **Remote OTBR** (`hass-otbr-docker` or HAOS OTBR Add-on) + Radio Co-Processor (Thread RCP over USB or Serial-over-IP `:6638`) | **100% Full** (`otbr_rest_url` + `otctl_cmd` + `matter.ws_url`) | Full router/child/neighbor tables (LQI/RSSI), MAC/IPv6 counters, SRP leases, RF energy scan, OMR host route verification, and full `ip6tables` control on `wpan0`. |
| **Option B (Embedded)** | **OTBR running on the coordinator hardware** (e.g., SLZB-MRxU / SLZB-06xU `:8080` REST API) | **Partial (REST-only + Matter WS)** (`otbr_rest_url` only, `otctl_cmd: ""`) | Reads Border Router state, channel, PAN/ExtPAN, masked dataset, and Matter L7 state via `python-matter-server`. Fine-grained `ot-ctl` tables (per-link LQI/RSSI, MAC/IP counters, SRP table) are unavailable without `ot-ctl`. Requires IPv6 enabled on the LAN. |

---

## 2. Why Thread Always Uses IPv6 (and Why You Do NOT Need ISP WAN IPv6)

- **Native IPv6 (6LoWPAN / RFC 4944):** Thread never carries IPv4. Every device has link-local (`fe80::/10`), Mesh-Local ULA (`fdxx::/64`), and Off-Mesh Routable (**OMR**, `fdxx::/64`) IPv6 addresses.
- **No ISP WAN IPv6 required:** The Border Router automatically generates private **ULA (`fd00::/8`)** prefixes locally.
- **Most common cause of "Paired but Unavailable" devices:** The Thread radio link is healthy, but the host running Home Assistant / `python-matter-server` lacks an IPv6 route to the OMR prefix or drops multicast **mDNS (`224.0.0.251` / `ff02::fb`, UDP/5353)** across VLANs or IGMP snooping.
- **Built-in check:** Thread2MQTT reads `/proc/net/ipv6_route` (non-root) to verify whether the host has an active route to the Border Router's OMR prefix (`ipv6_omr_route_ok`), displays each node's IPv6 OMR address in its Device Details view, and logs unmatched Thread/SRP entries under the `UNMATCHED` filter in **Logs**.

---

## 3. Matter Multi-Admin Compatibility (Amazon Alexa, Google Home, Apple Home)

- **Multi-Admin ECW:** Thread2MQTT identifies active Matter fabrics (`Home Assistant`, `Apple Home`, `Apple Keychain`, `Google Home`, `Amazon Alexa`) and can open a 300-second **Enhanced Commissioning Window (ECW)** on an already paired device so you can share it with Alexa, Google Home, or Apple Home without resetting it.
- **Ecosystem boundary:** Proprietary Border Routers (Echo, Nest Hub, HomePod, Apple TV) do not expose OTBR REST or `ot-ctl` APIs, so Thread2MQTT cannot read their internal radio tables directly. When devices are shared onto the same Thread fabric, Thread2MQTT surfaces them through your OTBR and `python-matter-server`.

---

## 4. Security Model (Zero-Trust & Zero-Secret)

1. **Loopback-first binding:** Defaults to `127.0.0.1:8099`. Always place behind a reverse proxy with IP allowlists or authentication if accessed remotely.
2. **Optional Bearer token:** Set `frontend.auth_token` (`${THREAD2MQTT_AUTH_TOKEN}`) to lock both the Web UI and all `/api/*` endpoints.
3. **Fail-closed defaults:** Ships with `advanced.read_only_mode: true`, disabling commissioning, ECW, and cluster writes even if enabled elsewhere.
4. **Hardened execution:** Zero external crates, non-root container (`USER 1000:1000`), `read_only: true`, `cap_drop: [ALL]`, strict whitelist of 15 read-only `ot-ctl` commands, and mandatory masking of `networkKey` and `PSKc` across `/api/state`, `/api/backup`, MQTT, and `/metrics`.

---

## 5. Backing Up Your Thread Dataset & Matter Fabric Safely

Thread2MQTT intentionally **never exposes plaintext `networkKey` or `PSKc` over HTTP** so a misconfigured LAN instance cannot leak your mesh master key.

To back up your mesh for disaster recovery (zero re-pairing after hardware loss), archive **both** of the following into an encrypted password manager / offline backup:

1. **Thread Active Operational Dataset (TLV hex — contains Network Key, Channel, PAN/ExtPAN, Mesh-Local Prefix, PSKc):**
   ```bash
   docker exec <otbr-container> ot-ctl dataset active -x
   # Also back up the persistent OTBR volume (e.g. /var/lib/thread or ./otbr_data/thread)
   ```
2. **Matter Fabric Credentials (`python-matter-server` persistent `/data` directory):**
   ```bash
   # Back up <matter-data>/*.json, credentials/, chip*.ini
   tar -czf matter_backup_$(date +%F).tar.gz ./matter_data ./otbr_data
   ```

---

## 6. Matter Pairing Codes vs Thread Dataset & Synchronized Home Assistant Renaming

- **Matter Pairing Codes (QR / 11-digit code):** By design of Matter SPAKE2+/PASE, a paired device never exposes its factory setup code back to the controller. Thread2MQTT lets you store an **optional local pairing-code memo** per device in `state.json` (masked by default in the UI and automatically redacted from MQTT and `/api/backup`). To share an already-paired device with Alexa, Google Home, or Apple Home, use **Multi-Admin ECW** (`Commissioning -> Open ECW Window`).
- **Synchronized Home Assistant Renaming:** Enabling `homeassistant.url`, `homeassistant.token` (`${HA_TOKEN}`), `homeassistant.allow_rename: true`, and `advanced.read_only_mode: false` unlocks the *"Update Home Assistant & Matter name"* checkbox in the rename modal and Device Settings tab. Thread2MQTT updates `name_by_user` via Home Assistant's WebSocket `config/device_registry/update` API and writes Matter `BasicInformation.NodeLabel` (`0/40/5`).
