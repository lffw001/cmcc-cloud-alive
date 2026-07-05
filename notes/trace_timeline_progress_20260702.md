# Trace timeline progress 2026-07-02

Goal: continue delivery-handoff section 10; stop guessing HTTP and map native ZIME/RAP transport from `reports/zime-transport-20260702-082921.jsonl`.

Implemented:
- Added `cmcc_cloud_alive/trace_timeline.py` to group JSONL by peerGroup/direction/function/payloadKind and emit key timeline/findings.
- Added CLI `python3 -m cmcc_cloud_alive.main trace-timeline ...`.
- Added unit test `test_trace_timeline_groups_family_and_loopback_spice`.
- `python3 -m unittest tests.test_python_modules -v` passes 35 tests.

Real trace report:
- Output: `reports/zime-transport-20260702-082921.timeline.json`.
- 53576 records, 0 invalid, keyTimelineTotal 404.
- family recvmsg top kinds: spice-data 4330, unknown 573, spice-mini-or-data 447, chuanyun-frame 113, spice-ack-sync 73, spice-ping 16, spice-pong 6, spice-set-ack 4.
- Findings currently: family/native true, loopback/plain-spice true, displayPath true, chuanyun false.

Known bug:
- `chuanyunOnFamilyObserved` was initially checked on keyTimeline events with `startswith("chuanyun-frame:")`; real classifier emits `chuanyun-frame` and keyTimeline filter may exclude chuanyun. Fix should check `groupedCounters` payloadKinds with startswith("chuanyun-frame") instead of `events` only.

Validation after fix:
- `python3 -m compileall -q cmcc_cloud_alive tests/test_python_modules.py` passed.
- `python3 -m unittest tests.test_python_modules -v` passed: 35 tests.
- Regenerated `reports/zime-transport-20260702-082921.timeline.json`.
- Updated findings: familyIsNativeTransport=true, loopbackHasPlainSpice=true, displayPathObserved=true, chuanyunOnFamilyObserved=true.
- keyTimelineTotal increased to 520 because `chuanyun-frame` is now treated as important timeline event.
