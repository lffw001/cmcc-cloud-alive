# Protocol runner progress 2026-07-03

User constraints:
- Communicate in Chinese.
- Target only the family cloud PC package currently identified as
  `家庭云电脑畅享版月包`.
- The cloud PC OS has been flashed back to Windows 10, so live verification must
  obtain fresh CAG/RAP material instead of reusing old endpoint values.
- CrossDesk is the user's remote-control software and must not be treated as the
  CMCC client.

Current completion state against Codming's protocol keepalive route:
- Done: SOHO login/token/list/status primitives.
- Done: CAG boot/connect-material acquisition and decoded `connectStr` summary.
- Done: rejected HTTP-only and CAG-only keepalive routes with independent power
  monitor evidence.
- Done: SPICE offline codecs for REDQ, DISPLAY_INIT, SET_ACK/ACK_SYNC,
  PING/PONG, Surface/Draw/MARK predicates, and RSA-OAEP ticket building.
- Done: ZIME/transport probe and trace analyzer.
- Done today: RAP data-frame analysis now extracts the candidate ZIME payload
  envelope: inner payload length, channel prefix, protected-payload length, and
  overhead. This is marked `traceOnly` and not replayable plaintext.
- Done today: `protocol-run` no longer attempts the wrong direct TCP/Chuanyun
  path when `connectStr type=rap`; it reports the remaining RAP/ZIME/SPICE gap
  explicitly.
- Done today: ZIME probe and analyzer now expose candidate
  `ZIMEPacketOutSpec` records from `TransportBatchImplC::OnSendData_Batch` /
  `ZIMETransport.OnSendData_Batch`. The inferred 0x68-byte layout contains
  iovec pointer/count and socket-address fields for protected UDP packet
  descriptors. This improves observability of the lsquic-to-RAP handoff but is
  still trace-only metadata, not replayable SPICE plaintext.

Evidence from refreshed analysis:
- Command:
  `python3 bin/cmcc_cloud_alive.py analyze-rap-zime reports/zime-transport-20260702-201034-ptrsym.jsonl --report-file reports/rap-zime-20260702-201034-ptrsym.json --sample-limit 80`
- Result summary:
  `transport=rap-zime-udp`, `primaryTunnelId=3aac08e4`,
  `displayPathObserved=true`, `ackPongMaintenanceSeen=true`.
- New envelope counts:
  `observed=16380`, channel prefix counts include `2=13645`, `4=903`,
  `8=667`, `6=576`, `1=231`, `5=213`, `3=123`, `7=13`, `0=9`.

Still missing:
- ZIME protected-payload encoder/encryption layer.
- A decision on whether to temporarily embed native `libZIMEDataEngine.so` for
  research-only packet generation, or fully reproduce the lsquic/ZIME state
  machine in Python.
- Python-created RAP/ZIME channel and stream lifecycle equivalent to official
  `ZIME_CreateDataChannel` / `ZIME_CreateDataStream`.
- SPICE main-channel link/auth and display-channel link/auth over that transport.
- Python-sent DISPLAY_INIT that causes real Surface/Draw/MARK from the cloud PC.
- Long verified run: at least 40 minutes, per-minute independent status checks,
  no official GUI contamination, no powered-off snapshot.

Verification run today:
- `python3 -m compileall -q cmcc_cloud_alive tests/test_python_modules.py`
- `python3 -m unittest discover -s tests -p 'test_python_*.py' -v`
- `scripts/build-zime-probe.sh`
- Result: 52 tests OK; probe builds to `build/research/zime-probe.so`.
