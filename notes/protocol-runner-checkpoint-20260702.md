# Protocol runner checkpoint 2026-07-02

Goal: implement family CMCC cloud-computer protocol runner: CAG boot/connect -> RAP/ZIME -> SPICE main/display; success requires DISPLAY_INIT + ACK/PONG + Surface/MARK activity and independent verified-run power monitor for ~40min.

SOP notes: reverse_skill_sop says perform concrete routed actions and tool-path verification; plan_sop says complex work must include exploration/plan/verify and not skip verification.

Key findings:
- Existing CAG HTTPS route is only boot/connect material, not final keepalive; docs/delivery-handoff.md warns CAG can mask shutdown / replace official session.
- /tmp/cag_report_full.json had final connectStrLength=5120 and decoded summary host=10.10.2.121 port=10048 type=rap serverType=hy, accessToken/cpsid present.
- State and public reports currently store only summaries; raw connectStr is not persisted.
- core.summarize_cag_response returns (summary, decoded). The decoded object is raw enough to extract connectInfo.connectStr before summary discards it.
- Latest direct cag_https_connect_report returned asyncQueries=0; connect response already has connectStr summary.

Tried/failed:
- Walking .tmp/state.json for connectStr found 0 strings (only bool summaries).
- CLI command cag-https-connect does not exist.
- Walking generated report found 0 connectStr strings because report summarizes away raw hex.

Next steps:
1. Recreate CAG connect request manually or call low-level cag_https_request + summarize_cag_response and persist decoded.connectInfo.connectStr securely to temp artifact.
2. Decode via core.decode_csap_connect_str / parse_connect_str_args; use host/port/key/accessToken/cpsid.
3. Implement a minimal ZIME/SPICE runner module + CLI, then unit-test and short live smoke test.
