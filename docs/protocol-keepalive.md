# Protocol Keepalive Notes

## Verdict

The active target is protocol-level desktop keepalive through the native
family-edition Linux transport:

```text
SOHO account/list/status
  -> CAG boot/connect material
  -> RAP/ZIME transport
  -> SPICE main channel
  -> SPICE display channel
  -> DISPLAY_INIT
  -> ACK/PONG maintenance
  -> independent power-state proof
```

Pure HTTP visible timers and CAG HTTPS refresh are not active keepalive
solutions.

The implementation scope is restricted to `家庭云电脑畅享版月包`. The cloud PC
guest OS is currently Win10 again; that changes the desktop content, not the
outer family Linux client transport under study.

## Why HTTP Was Rejected

Connected-client HARs exposed these visible SOHO timers:

```text
/cc/cloudPc/heartbeat/v2
/cc/cloudPc/infoReport/v2
/system/logReport/config/v2
```

Those requests can return accepted business responses, but long tests showed
the family desktop still powers off. Therefore they are telemetry/supervision
evidence, not desktop-session keepalive.

The enterprise-style endpoints from the Hansiy article were not present in the
family captures:

```text
/resource/desktopUptime
/session/machineConnect
/machine/pushConnectEventData
```

## Why CAG Was Rejected

CAG HTTPS can obtain decoded connection material and can start or pull the VM
back to running. That is not the same as keeping an existing desktop display
session alive.

Observed failures:

- Official GUI cross-check showed CAG refresh can replace/kick the active
  official desktop session.
- `CAG + HTTP prime` still reached `已关机` under independent monitoring.
- CAG after-status can mask the failure because a later CAG round may pull the
  VM back to `运行中`.

CAG remains useful only for boot/connect material acquisition.

## Codming Route Applied To Family Linux

Codming's key lesson is that the desktop stays alive only after the display
path is initialized, not after account HTTP or connection-material HTTP.

The family Linux route is not a direct copy of macOS SCG `:10800`. Captured and
decoded `connectStr` values show a RAP/ZIME route:

```text
type=rap
server-type=hy
vmport=5100
accessToken=<present>
cpsid=<present>
```

The installed Linux client confirms this split:

```text
libvdconn.so.1.0.0            CAG/connect material and process launch
libZIMEDataEngine.so          RAP/ZIME data transport
libspice-client-glib-zte...   SPICE main/display protocol
uSmartView_VDI_Client         GUI shell around SPICE display
```

Relevant native symbols:

```text
ZIME_CreateDataEngine
ZIME_Init
ZIME_CreateDataChannel
ZIME_CreateDataStream
ZIME_SendData
ZIME_ReceiveData
ZIME_DataChannelProcess2
spice_channel_send_link
spice_channel_recv_link_res
spice_channel_send_vapp_ticket_key
main_channel_linked
display_handle_surface_create
display_handle_mark
display_handle_draw_copy
hand_display_channel_ping_msg
```

## Current Codec Layer

`cmcc_cloud_alive/spice_protocol.py` provides offline protocol building blocks:

- REDQ link header/message encode/decode.
- SPICE mini/data message encode/decode.
- `DISPLAY_INIT` encode.
- SET_ACK decode and ACK_SYNC encode.
- PING/PONG handling.
- Chuanyun 24-byte frame encode/decode.
- RSA public-key DER parse and OAEP ticket encryption.
- Success predicate requiring display-init plus Surface/Draw/MARK evidence.

`spice-offline-proof` validates these local codecs. It is not a real cloud
keepalive proof.

## Dynamic Probe

`research/zime-probe.c` is an `LD_PRELOAD` probe for the official Linux client
or SDK. It logs exported ZIME API calls without changing behavior.

Build:

```bash
scripts/build-zime-probe.sh
```

Run:

```bash
ZIME_PROBE_LOG=reports/zime-official.jsonl \
  scripts/run-zime-probe.sh -- <official-client-or-sdk-command>
```

Default mode is `ZIME_PROBE_MODE=low`. It is designed for the first recapture
after the observed `SPICE_OUTBAND` / `signal[11]` failure: only `uSmartView`
processes are logged by default, exported ZIME C API calls are traced, callback
table wrapping is off, and libc socket/read/write/send/recv, SSL, and C++
callback symbol interpose are not compiled into the default `.so`.

Escalate capture depth explicitly:

```bash
ZIME_PROBE_MODE=transport scripts/run-zime-probe.sh -- <official-client-or-sdk-command>
ZIME_PROBE_MODE=callback scripts/run-zime-probe.sh -- <official-client-or-sdk-command>
ZIME_PROBE_MODE=full scripts/run-zime-probe.sh -- <official-client-or-sdk-command>
ZIME_PROBE_MODE=cpp scripts/run-zime-probe.sh -- <official-client-or-sdk-command>
```

`low/callback` use `build/research/zime-probe.so`; `transport/full` use
`build/research/zime-probe-transport.so`; `cpp` uses
`build/research/zime-probe-cpp.so`. This keeps an intrusive C++ interpose build
from contaminating the next low-intrusion official trace.

Expected useful records:

```text
ZIME_CreateDataChannel     channel ID allocation
ZIME_CreateDataStream      stream ID allocation
ZIME_SendData              client-to-transport payloads
ZIME_ReceiveData           transport-to-client payloads
ZIME_DataChannelProcess2   transport event loop
zime_packet_spec           candidate protected UDP packet descriptors
```

The probe classifies visible payload prefixes as `spice-link`,
`spice-display-init`, `spice-surface-create`, `spice-mark`,
`spice-ping`, `spice-pong`, or `chuanyun-frame` when possible.

Analyze a probe log:

```bash
python3 bin/cmcc_cloud_alive.py analyze-zime-probe reports/zime-official.jsonl \
  --report-file reports/zime-official.analysis.json
```

The analyzer summarizes payload kinds, channel and stream IDs, and whether the
trace reached `DISPLAY_INIT`, ACK/PONG maintenance, and display activity. This
is protocol trace evidence only; it is not proof of desktop keepalive without a
verified long run.

The analyzer also reports `zimePacketSpecs` when the probe observes
`TransportBatchImplC::OnSendData_Batch` or `ZIMETransport.OnSendData_Batch`.
Use `ZIME_PROBE_MODE=callback` or `ZIME_PROBE_WRAP_CALLBACKS=1` for new captures
that need callback-table packet specs; reserve `ZIME_PROBE_MODE=cpp` for cases
where symbol-level C++ callback interpose is explicitly required. The
candidate layout is inferred from `LsquicCallbacksImpl::PacketsOutBatch`: a
0x68-byte entry containing an iovec pointer/count, local and destination
sockaddr pointers, a copied sockaddr-like block, and an address-length byte.
This identifies the handoff from lsquic packet generation to RAP/ZIME UDP send,
but the bytes described there are already protected UDP payloads, not SPICE
plaintext.

`analyze-rap-zime` also separates transport evidence. `rap-zime-udp` with a
primary tunnel ID can parameterize the UDP scaffold. `family-native-spice-trace-only`
or `external-tls-trace-only` means the trace is useful for protocol mapping, but
it is not enough to drive the RAP/ZIME runner because the UDP tunnel target or
tunnel ID was not observed.

The current RAP data-frame analysis also reports a `zimePayloadEnvelope` when
the protected ZIME payload shape is visible. For display-like frames observed in
official traces, the RAP payload begins with a little-endian inner payload
length, while the third byte of the RAP post-length field matches the local
SPICE channel prefix seen in loopback frames. These facts are useful for
reconstructing the encoder, but the protected payload is still not plaintext
SPICE and must not be replayed as proof.

## Native Bridge

`cmcc_cloud_alive/zime_native_bridge.py` is a research-only bridge around the
installed `libZIMEDataEngine.so`. It defaults to inspection only: it checks the
library path, required exports, optional exports, and the inferred ctypes
structure layout without calling native functions.

```bash
python3 bin/cmcc_cloud_alive.py zime-native-bridge
```

Native execution is explicit and offline:

```bash
python3 bin/cmcc_cloud_alive.py zime-native-bridge \
  --display-init \
  --allow-native-run \
  --report-file reports/zime-native-bridge-display-init.json
```

That mode uses fake external transport callbacks. Its useful output is whether
the native engine produces `native_transport_send` or `native_transport_batch`
records for known SPICE payloads. With the current default wait gate, a fake
transport run should stop at `native_channel_created_pending` instead of
creating a user stream against an inactive channel; use
`--wait-channel-created-ticks 0` only for legacy immediate-stream comparisons.
It is still not desktop keepalive proof, does not replace `protocol-run`, and
does not remove the need for a 40-minute
`verified-run`.

Current native finding:

- `u16BaseMTU=1200` fails `ZIME_CreateDataChannel` with invalid parameter.
- `u16BaseMTU=1452` reaches `ZIME_CreateDataChannel ret=0`.
- `ZIME_DataChannelProcess2` after channel creation emits a complete
  `native_transport_batch`; the captured payload is classified as
  `zime-udp-reserved4:quic-long-header-candidate`.
- `ZIME_CreateDataStream` still returns `7` / `Channel does not exist` because
  fake transport has not delivered any real remote handshake response, so the
  QUIC/ZIME channel is not yet active.

The bridge now has an explicit UDP-backed external transport mode. When
`--udp-transport-target` is supplied, native packet-out callbacks are sent to
UDP and responses are routed back through `ZIME_ReceiveData` followed by
`ZIME_DataChannelProcess2`. The mode supports raw native UDP and RAP data-frame
wrapping:

```bash
python3 bin/cmcc_cloud_alive.py zime-native-bridge \
  --allow-native-run \
  --read-iov-payload \
  --runner-input reports/rap-zime-runner-input.json
```

`--runner-input` reuses `analyze-rap-zime` output to fill the RAP UDP target,
tunnel ID, RAP wire mode, and channel-context remote address. Explicit
`--udp-transport-target` / `--udp-rap-tunnel-id` values override the file when
needed. The RAP data payload envelope is selected explicitly with
`--udp-rap-payload-envelope`:

- `raw`: previous behavior, native packet-out is the RAP data-frame payload.
- `len16`: prepend a little-endian 16-bit protected-payload length and strip it
  before `ZIME_ReceiveData`.
- `strip-reserve4-len16`: strip the native packet-out's four-byte UDP reserve
  before adding the 16-bit length, then restore a zero reserve prefix on
  received RAP data before feeding the native engine.

Short live experiments should try `raw`, then `len16`, then
`strip-reserve4-len16` while keeping `--udp-ztec-prime` and the trace-derived
RAP frame template constant. A response only advances the milestone; it is not
desktop keepalive proof.

The bridge also exposes `--udp-packet-out-iov-mode concat|split`. `concat` keeps
the previous behavior and sends the full captured iovec payload as one
datagram. `split` sends each iovec segment as its own UDP/RAP datagram; use it
only for short live comparisons when native batch records show multi-segment
payloads that do not match official RAP data-frame sizes.

`analyze-rap-zime` now exports `runnerInput.rapDataFrameSendTemplates`, a
send-side sequence of observed 0x81 data-frame header templates keyed with
`payloadKind`, `payloadLength`, and whether the ZIME payload envelope was
present. `zime-native-bridge --udp-rap-template-mode auto` uses that sequence
by payload kind when it is present. `static` keeps the single
`rapDataFrameTemplate` behavior, while `sequence` walks the observed templates
without matching payload kind.

The bridge report also contains `nativeMilestones`. The key sequence is:

```text
channelCreateOk
nativePacketOutSeen
nativeUdpSent
nativeUdpReceived
receiveDataOk
nativeChannelCreated
streamCreateOk
displayInitSendOk
displayPathObserved
verifiedRunPassed
```

Only the final display-path observation plus verified-run can count as success.
Earlier milestones only identify where the RAP/ZIME handshake is currently
stopping.

The native bridge waits for `native_channel_created` before attempting
`ZIME_CreateDataStream`. The default extra wait is controlled by
`--wait-channel-created-ticks`; pass `0` only for legacy offline probes that
need the old immediate-stream behavior. If the callback never arrives, the
report should remain at `native_channel_created_pending` and must not attempt
`DISPLAY_INIT`.

This is transport plumbing only. It still needs a live RAP/ZTEC target and
trace validation before we can claim the QUIC/ZIME channel becomes active.
Only after that can the bridge create a user stream and send `DISPLAY_INIT`.

`rap-zime-udp-probe` now accepts a bridge report as payload input:

```bash
python3 bin/cmcc_cloud_alive.py rap-zime-udp-probe \
  --runner-input reports/rap-zime-runner-input.json \
  --native-report reports/zime-native-bridge-packetout-classified.json
```

This only wires local artifacts together. It does not prove the RAP payload
wrapper is correct, and it does not mean replaying a captured packet is an
acceptable keepalive implementation.

## Mandatory Proof Harness

Every real protocol experiment must run under `verified-run` or an equivalent
per-minute independent status monitor. The verifier launches the experiment,
polls cloud power state every 60 seconds, and terminates the experiment as soon
as the VM is `已关机` or otherwise not running.

```bash
CMCC_ALIVE_STATE=.tmp/state.json scripts/verified-run.sh \
  --duration 2400 \
  --interval 60 \
  --report-file reports/<experiment>.verified.json \
  <userServiceId> -- <protocol-runner-command>
```

Success requires the command to complete normally or remain healthy for the
requested window, no status-check errors, and `poweredThroughout=true` for the
full 40 minutes.

## Implementation Plan

1. Capture an official successful desktop session with the ZIME probe.
2. Extract channel/stream creation order and identify where SPICE link,
   ticket auth, main channel, display channel, and `DISPLAY_INIT` appear.
3. Map RAP/ZIME framing enough to send the same display-channel sequence from
   Python without launching `uSmartView_VDI_Client`.
4. Either use the native bridge to generate valid protected packet-out bytes or
   implement the ZIME/lsquic protected-payload layer directly.
5. Implement a protocol runner module separate from HTTP and CAG helpers.
6. Run a 40-minute proof through `scripts/verified-run.sh`.
7. Mark the route successful only if every minute remains running and the trace
   reaches display Surface/MARK activity.

## Non-Success Signals

These are not success:

```text
heartbeat returns 2000/4041
infoReport returns 2000
logReport config returns 2000
CAG returns connectStr
status becomes running immediately after CAG
spice-offline-proof passes
zime-native-bridge inspect/native fake-transport run passes
zime-native-bridge UDP transport local fake-server tests pass
```

The success signal is a long real run where the independent power monitor never
observes shutdown and the protocol trace shows display-channel activity.
