#!/usr/bin/env bash
# Development stack on loopback: vpn-labpeer (a WireGuard peer with lab services) + vpnd manager +
# vpnd controller, in a private state directory with a scratch ~/.ssh. It never touches an
# installed VPN Manager (other state directory, other ports).
#
#   scripts/dev-stack.sh [--base PORT] [--state DIR] [--seed] [--release] [--dev-origin URL]
#                        [--lab-forward PORT=ADDR]...
#
#   UI and API   http://127.0.0.1:<base>          (default base 28765)
#   labpeer      udp 127.0.0.1:<base+1>; test API http://127.0.0.1:<base+2> (POST /dial connects in
#                to the client's tunnel address: port-forward tests)
#   Gateways     127.0.0.1:<base+10> (Mixed), <base+11> (SOCKS5) when seeded
#   --seed       on a new state directory: import the lab profile, add a security profile that
#                allows the lab ranges, a lab DNS profile, a connection with two Gateways, start it
#   --lab-forward  PORT=ADDR: the lab peer relays 10.99.0.1:PORT in the tunnel to ADDR on this
#                host's loopback (a real service behind the lab server, e.g. an unprivileged sshd)
#
# Stops everything it started on Ctrl-C or SIGTERM. Logs: <state>/{lab,mgr,ctl}.log.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=${PWD}

BASE=28765
STATE=""
SEED=0
PROFILE_DIR=debug
DEV_ORIGIN=""
LAB_ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --base)
      BASE=$2
      shift 2
      ;;
    --state)
      STATE=$2
      shift 2
      ;;
    --seed)
      SEED=1
      shift
      ;;
    --release)
      PROFILE_DIR=release
      shift
      ;;
    --dev-origin)
      DEV_ORIGIN=$2
      shift 2
      ;;
    --lab-forward)
      LAB_ARGS+=(--forward-tcp "$2")
      shift 2
      ;;
    *)
      echo "unknown option: $1" >&2
      exit 2
      ;;
  esac
done
STATE=${STATE:-${TMPDIR:-/tmp}/vpnm-dev-${BASE}}
BIN=${ROOT}/target/${PROFILE_DIR}
for b in vpnd vpn-labpeer; do
  [[ -x "${BIN}/${b}" ]] || {
    echo "missing ${BIN}/${b}: run cargo build${PROFILE_DIR/debug/} first" >&2
    exit 1
  }
done

API=http://127.0.0.1:${BASE}
LAB=127.0.0.1:$((BASE + 1))
mkdir -p "${STATE}/home/.ssh"
chmod 700 "${STATE}" "${STATE}/home" "${STATE}/home/.ssh"
FRESH=0
[[ -d "${STATE}/state" ]] || FRESH=1

pids=()
# `${a[@]+"${a[@]}"}` expands an empty array to nothing: macOS's bash 3.2 treats a plain
# "${a[@]}" of an empty array as unset under `set -u`.
stop() {
  for p in ${pids[@]+"${pids[@]}"}; do kill -TERM "${p}" 2>/dev/null || true; done
  wait 2>/dev/null || true
}
trap stop EXIT INT TERM

"${BIN}/vpn-labpeer" serve --listen "${LAB}" --client-config "${STATE}/lab.conf" --keys "${STATE}/lab.keys" \
  --api "127.0.0.1:$((BASE + 2))" ${LAB_ARGS[@]+"${LAB_ARGS[@]}"} 2>"${STATE}/lab.log" &
pids+=($!)
# The seed imports the client configuration the peer writes when it starts; the manager and the
# controller can be ready before it is there.
for _ in $(seq 1 100); do
  [[ -s "${STATE}/lab.conf" ]] && break
  sleep 0.1
done
[[ -s "${STATE}/lab.conf" ]] || {
  echo "vpn-labpeer did not start (see ${STATE}/lab.log)" >&2
  exit 1
}
"${BIN}/vpnd" manager --state-dir "${STATE}/state" --ssh-dir "${STATE}/home/.ssh" 2>"${STATE}/mgr.log" &
pids+=($!)
for _ in $(seq 1 50); do
  [[ -S "${STATE}/state/run/manager.sock" ]] && break
  sleep 0.1
done
ctl=("${BIN}/vpnd" controller --port "${BASE}" --state-dir "${STATE}/state")
[[ -n "${DEV_ORIGIN}" ]] && ctl+=(--dev-origin "${DEV_ORIGIN}")
"${ctl[@]}" 2>"${STATE}/ctl.log" &
pids+=($!)
for _ in $(seq 1 100); do
  curl -s "${API}/v1/system/status" | grep -q '"manager_connected":true' && break
  sleep 0.1
done

if [[ "${SEED}" = 1 ]] && [[ "${FRESH}" = 1 ]]; then
  H=(-H "Origin: ${API}" -H "content-type: application/json")
  post() {
    local k
    # As before, a missing uuidgen leaves the header empty rather than stopping the seed.
    k=$(uuidgen | tr '[:upper:]' '[:lower:]') || true
    curl -sf -X POST "${H[@]}" -H "Idempotency-Key: ${k}" --data "$2" "${API}$1"
  }
  field() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval('d' + sys.argv[1]))" "$1"; }
  body=$(python3 -c "import json,sys; print(json.dumps({'mode':'commit','name':'Lab peer（東京）','config':open(sys.argv[1]).read(),'location':{'country_code':'JP','country':'日本','city':'東京','server':'lab-tyo-01'}}))" "${STATE}/lab.conf")
  profile=$(post /v1/profiles/import "${body}" | field "['profile']['id']")
  sec=$(post /v1/security-profiles '{"name":"Lab 內網","allow_private":["10.99.0.0/24","fd99::/64"],"blocked_ports":[],"blocklists":[],"auto_ban":{"enabled":false,"window_secs":10,"threshold":100,"ban_secs":900,"max_bans":10000}}' | field "['id']")
  dns=$(post /v1/dns-profiles '{"name":"Lab DNS","servers":[{"transport":"udp","address":"10.99.0.1:53"},{"transport":"tcp","address":"10.99.0.1:53"}],"cache":{"max_entries":4096,"max_ttl_secs":3600,"negative_ttl_secs":60},"query_timeout_ms":3000,"attempts":2}' | field "['id']")
  inst=$(post /v1/instances "{\"name\":\"東京實驗室出口\",\"profile_id\":\"${profile}\",\"dns_profile_id\":\"${dns}\",\"security_profile_id\":\"${sec}\"}" | field "['spec']['id']")
  post /v1/gateways "{\"instance_id\":\"${inst}\",\"name\":\"瀏覽器\",\"kind\":\"mixed\",\"port\":$((BASE + 10)),\"udp\":true,\"enabled\":true,\"max_connections\":1024}" >/dev/null
  post /v1/gateways "{\"instance_id\":\"${inst}\",\"name\":\"終端機工具\",\"kind\":\"socks5\",\"port\":$((BASE + 11)),\"udp\":true,\"enabled\":true,\"max_connections\":256}" >/dev/null
  post "/v1/instances/${inst}/actions" '{"action":"start"}' >/dev/null
  echo "seeded: profile=${profile} instance=${inst} gateways=$((BASE + 10)),$((BASE + 11))"
fi

echo "dev stack up: ${API} (state ${STATE})"
wait
