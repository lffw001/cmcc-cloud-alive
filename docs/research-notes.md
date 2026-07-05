# Research Notes

## External References

- <https://hansiy.net/p/86b7133e>
- <https://codming.com/posts/cmcc-cloud-computer-keepalive/>

The Hansiy article is valuable for workflow, not for blindly copying protocol
constants. It targets a different edition/platform. This project targets the
family Linux client.

Reusable lessons:

- Source analysis gives hypotheses; capture decides runtime truth.
- Separate account/login liveness from desktop-session liveness.
- Preserve business errors; do not hide them as network errors.
- Validate each protocol layer with a small harmless request before building a
  loop.
- Field deletion and replay tests must be done against the family capture, not
  against another edition's assumptions.

## Family Linux Findings

The Python implementation currently proves:

- SOHO signing and RSA request-body encryption are accepted.
- Password login works.
- Cloud list works.
- CAG HTTPS can start or wake the cloud PC and return decoded connection
  material.
- `/cc/cloudPc/heartbeat/v2` can be called as a probe.

The current captures do not show an HTTP endpoint that keeps the desktop
session alive without the native desktop transport. HTTP visible timers and
CAG refresh are rejected as active keepalive routes.

Latest connected-client evidence:

- `/home/demo/下载/soho.komect.com_2026_07_01_15_43_16.har` covers about
  34m40s while the official client kept the desktop connected.
- Visible HTTP timers in that capture:
  `/cc/cloudPc/heartbeat/v2` about every 30 seconds,
  `/cc/cloudPc/infoReport/v2` about every 121 seconds, and
  `/system/logReport/config/v2` about every 120/180 seconds.
- The desktop did not sleep in this capture, but the official native desktop
  client was connected at the same time. Therefore this is a connected-client
  baseline, not proof that HTTP alone keeps the desktop alive.
- Previous 5-minute HTTP replay failed at 25m09s despite accepted heartbeat,
  infoReport, and point responses. Previous connect-event/CAG research also
  caused the official macOS client to receive `4043 该云电脑已在其他设备上登录`.
- `/home/demo/下载/terminalprobe.soho.komect.com_2026_06_30_19_22_00.har`
  shows Windows connected-client telemetry: heartbeat, infoReport, point, and
  terminalprobe base/peripheral/performance uploads. It still does not show an
  enterprise-style `/resource/desktopUptime` endpoint, and terminalprobe remains
  telemetry.
- The combined Windows/macOS/Linux/terminalprobe HAR audit in
  `docs/evidence/cross-platform-har-summary-20260701.json` covers 487 records
  and 37 endpoints. All endpoints are classified; no unknown HTTP desktop
  candidate remains, and the enterprise-blog uptime/session endpoints are still
  absent.

## Capture Rule

The next authoritative artifact should be a ZIME/SPICE trace captured while the
official family Linux client is inside the desktop. Existing SDK plaintext
JSONL captures are useful for CAG startup analysis, but they have not exposed a
desktop-session HTTP endpoint.

For the next protocol trace:

1. Connect the desktop with the official client on this machine and capture the
   ZIME probe.
2. Extract channel/stream creation order and SPICE link/display messages.
3. Confirm where `DISPLAY_INIT`, Surface creation, MARK, ACK, and PONG appear.
4. Build the Python protocol runner from that family Linux trace.
5. Prove it with an independent per-minute power monitor.

## Active Order

Docker packaging is abandoned for this project. Keep the implementation focused
on a local Python/protocol tool until the protocol route is proven.

Route priority:

1. RAP/ZIME/SPICE display-channel protocol reproduction.
2. Independent 40-minute power-state proof.
3. Only if protocol evidence proves unavoidable session ownership, document the
   final tool as session-owning rather than non-disruptive.

The Codming article is useful methodology and a display-channel hypothesis; it
is not proof for this family-edition Linux route by itself.
