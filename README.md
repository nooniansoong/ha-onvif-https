# ONVIF over HTTPS (events) — Home Assistant custom integration

Home Assistant's **core ONVIF integration talks plain HTTP only** and blindly
follows the XAddr URLs a device advertises. Some NVRs/cameras (e.g. Raysharp /
CDoubles OEM NVRs) serve ONVIF **only over HTTPS** — often with TLS multiplexed
on **port 80** — *and* advertise `http://…` XAddrs they then refuse. Core can't
connect to those.

This integration does the one thing core can't: it subscribes to **ONVIF
events over HTTPS** and surfaces them in HA.

- Hand-built SOAP (no `onvif-zeep`), always targets `https://host:port`.
- Accepts self-signed device certificates (`verify_ssl` off by default).
- Rewrites the broken `http://` subscription reference the device returns.
- WS-Security `UsernameToken` / `PasswordDigest` auth.
- Long-poll **PullPoint** loop with auto-renew and auto-reconnect.

It is **events-only** (motion / line-crossing / person / tamper …). For live
video, keep using go2rtc / WebRTC or the core ONVIF/generic-camera for the
streams — this fills the event gap those can't.

## What you get

For every notification the device emits, the integration:

1. **Fires an HA event** `onvif_https_event` on the bus — automate on this
   directly (most reliable), e.g.:

   ```yaml
   trigger:
     - platform: event
       event_type: onvif_https_event
   condition:
     - "{{ 'CrossLine' in trigger.event.data.topic or 'LineDetector' in trigger.event.data.topic }}"
   action:
     - service: notify.mobile_app_YOUR_PHONE
       data:
         title: 越線警報
         message: "Line crossed on channel {{ trigger.event.data.channel }}"
   ```

   Event data: `topic`, `name`, `channel`, `active`, `utc`, `source`, `data`.

2. **Creates a `binary_sensor`** per `(topic, channel)` as events appear
   (device_class motion/occupancy/tamper), auto-off after *Auto-off delay*
   seconds. Use these on dashboards or as simpler automation triggers.

## Install (HACS custom repo)

1. HACS → ⋮ → **Custom repositories** → add this repo's URL, category
   **Integration**.
2. Install **ONVIF over HTTPS (events)**, restart HA.
3. Settings → Devices & Services → **Add Integration** → *ONVIF over HTTPS*.
4. Fill in host, **port 80**, ONVIF username/password, leave *Verify TLS* off.

(Or copy `custom_components/onvif_https/` into your HA `config/custom_components/`
manually and restart.)

## Test first, without HA

`test_events.py` is a dependency-free validator. Run it on any machine that can
reach the device and confirm it emits line-crossing before installing:

```bash
python3 test_events.py 192.168.10.150 80 admin 'YOURPASS'
# list only the topics it supports:
python3 test_events.py 192.168.10.150 80 admin 'YOURPASS' --topics-only
```

Walk across your line while it runs — matching topics are starred ⭐.

## Finding your line-crossing topic

Different firmwares name it differently:
`tns1:RuleEngine/LineDetector/Crossed`, `tns1:RuleEngine/CellMotionDetector/Motion`,
`tns1:RuleEngine/FieldDetector/ObjectsInside`, a vendor `tns1:…/PeaDetect`, etc.
Run the tester (or watch Developer Tools → Events → `onvif_https_event` in HA)
to see the exact string your device sends, then match on it in your automation.

## Notes / limits

- Events-only by design; no camera, PTZ or media entities.
- One config entry per device. For an NVR that aggregates channels, the
  `channel` field distinguishes them.
- If the device requires WS-Addressing quirks your firmware rejects, capture a
  PullMessages response and open an issue.
