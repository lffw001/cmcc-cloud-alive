# Protocol trace checkpoint 2026-07-02

Context: /home/demo/cmcc-cloud-alive is a symlink to /home/demo/restore/cmcc-cloud-alive.

Key findings:
- trace-timeline report findings are already true after conservative grouping fixes.
- Family-like transport rows are mixed with local IPC/loopback traffic; do not treat all family peer rows as cloud protocol.
- Real trace contains `ssl_buffer` plaintext rows from SSL_write/SSL_read.
- Official client sends many 8-byte SSL plaintext packets such as `2a08040000000000`, `2a07040000000000`, `2a03040000000000`, `2a02040000000000`, `2a01040000000000`.
- These decode as a short/mini SPICE-like header: little-endian type first (`0x082a`, `0x072a`, etc.) and size=4, but they are not the current runner's 18-byte data-header ACK/PONG messages.
- Current `zime_probe.classify_payload` names only known SPICE_TYPES/chuanyun frames, so these official keepalive/control mini packets remain `unknown`/generic.

Tried approaches:
- Direct display-init hex search in transport rows found no candidate.
- fd/peer grouping showed many mixed local streams; moved strategy to SSL plaintext layer.
- Compared current `spice_protocol.encode_display_init/ack/pong` bytes with true SSL_write packets; mismatch confirms runner is incomplete for official short keepalive packets.

Next steps:
1. Add conservative classification/reporting for unknown short mini SPICE-like packets in `zime_probe` (do not overname exact semantic unless proven).
2. Add tests with sample `2a08040000000000` and ensure trace analyze surfaces counts/samples.
3. Re-run unit tests and real report.

## Update after SSL-only short-mini gating

Problem found during real report generation:
- A global u16 short-mini fallback over-classified arbitrary `transport_buffer` fragments as `spice-mini-unknown`, e.g. `0x020a` thousands of times.
- The real short control evidence is specifically from `ssl_buffer` plaintext (`SSL_write`) sample `2a08040000000000`.

Implemented direction:
- `zime_probe.classify_payload(data, allow_short_mini=False)` keeps short `<u16 type,u16 size>` fallback disabled by default.
- `zime_probe.analyze()` enables that fallback only for `record["event"] == "ssl_buffer"`.
- Tests should assert default classification remains `unknown`, while explicit `allow_short_mini=True` gives `spice-mini-unknown:0x082a` and analyze still counts the SSL sample.

Next verification:
- Re-run related tests + full `tests.test_python_modules`.
- Regenerate `reports/zime-probe-ssl-short-20260702.json`; confirm no massive transport over-classification and SSL short sample remains counted.

## Update after sample selector verification

Implemented `_select_samples(samples, limit=80)` in `cmcc_cloud_alive/zime_probe.py`:
- Keeps the first 24 samples for context.
- Always includes all `ssl_buffer` samples and all `payloadKind == spice-mini-unknown:0x082a` samples before filling to the limit.
- This prevents the real SSL short-control evidence (`index=53211`, `SSL_write`, `hexPrefix=2a08040000000000`) from being dropped when many earlier transport samples exist.

Verification before final test:
- Related 4 tests OK.
- Full `tests.test_python_modules` OK (36 tests).
- Regenerated `reports/zime-probe-ssl-short-20260702.json`: `records=53576`, `sample_count=80`, `payloadKindCounts.spice-mini-unknown:0x082a=1`, `spice-mini-unknown:0x020a` absent, and sample evidence includes `index=53211` SSL_write short-control.

Added regression test:
- `test_zime_probe_classifies_ssl_short_spice_like_control_packets` now creates 90 filler transport records before the SSL short-control record and asserts the buried `0x082a` sample is still selected.
