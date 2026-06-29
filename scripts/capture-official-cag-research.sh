#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
Usage:
  sudo scripts/capture-official-cag-research.sh <userServiceId> [durationSeconds]

This is a research-only capture helper. It briefly starts the legacy official
SDK wrapper through `yidongyun keepalive` and captures CAG UDP traffic so the
protocol implementation can be compared against real client behavior.

It is not used by the protocol keepalive implementation and is not intended for
Docker runtime.
USAGE
  exit 2
}

USER_SERVICE_ID="${1:-}"
DURATION="${2:-20}"
CAG_HOST="${CMCC_CAG_HOST:-111.31.3.182}"
CAG_PORT="${CMCC_CAG_PORT:-8899}"
OUT_DIR="${CMCC_RESEARCH_OUT_DIR:-/tmp}"

if [[ -z "$USER_SERVICE_ID" ]]; then
  usage
fi

if ! [[ "$DURATION" =~ ^[0-9]+$ ]] || [[ "$DURATION" -lt 5 ]]; then
  echo "durationSeconds must be an integer >= 5" >&2
  exit 2
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "run this script with sudo/root so tcpdump can capture packets" >&2
  exit 1
fi

if ! command -v tcpdump >/dev/null 2>&1; then
  echo "tcpdump is required" >&2
  exit 1
fi

if ! command -v yidongyun >/dev/null 2>&1; then
  echo "legacy yidongyun CLI is required for this research helper" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
TS="$(date +%Y%m%d-%H%M%S)"
PCAP="${OUT_DIR}/cmcc-cloud-alive-research-cag-${TS}.pcap"
SDK_LOG="${OUT_DIR}/cmcc-cloud-alive-sdk-${TS}.log"
TCPDUMP_LOG="${OUT_DIR}/cmcc-cloud-alive-tcpdump-${TS}.log"

cleanup() {
  if [[ "${TCPDUMP_PID:-}" ]] && kill -0 "$TCPDUMP_PID" 2>/dev/null; then
    kill -INT "$TCPDUMP_PID" 2>/dev/null || true
    wait "$TCPDUMP_PID" 2>/dev/null || true
  fi
  pkill -TERM -f 'bootCypc|uSmartView_VDI_Client|chuanyun-vdi-client' 2>/dev/null || true
}
trap cleanup EXIT INT TERM

tcpdump -i any -U -w "$PCAP" "udp and host ${CAG_HOST} and port ${CAG_PORT}" >"$TCPDUMP_LOG" 2>&1 &
TCPDUMP_PID="$!"
sleep 2

set +e
yidongyun keepalive --user-service-id "$USER_SERVICE_ID" --duration "$DURATION" >"$SDK_LOG" 2>&1
SDK_STATUS="$?"
set -e

cleanup
trap - EXIT INT TERM

cat <<EOF
pcap=$PCAP
sdk_log=$SDK_LOG
tcpdump_log=$TCPDUMP_LOG
sdk_status=$SDK_STATUS
extract:
  node bin/cmcc-cloud-alive.js extract-cag-handshake "$PCAP"
EOF

exit "$SDK_STATUS"
