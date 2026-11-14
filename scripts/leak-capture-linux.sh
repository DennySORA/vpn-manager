#!/usr/bin/env bash
# Leak capture on Linux, rootless: packet-level evidence that protected traffic never leaves
# outside the WireGuard tunnel (acceptance criteria AC-16, AC-20, AC-26, AC-31 and the Linux
# part of AC-70).
#
#   scripts/leak-capture-linux.sh (--src DIR [--build] | --bin DIR) [--base PORT] [--out DIR]
#                                 [--nic auto|dummy|tun] [--keep-work]
#
#   --src DIR   source tree with release binaries in DIR/target/release (--build: build them
#               first: cargo build --release -p vpnd -p vpnctl -p vpn-labpeer)
#   --bin DIR   directory holding prebuilt vpnd and vpn-labpeer (this script's own
#               scripts/dev-stack.sh is used)
#   --base      dev-stack base port (default 28765; the run has its own network namespace,
#               so it cannot collide with anything on the host)
#   --out       output directory (default ~/vpnm-capture/run-<time>); refused on tmpfs
#   --nic       the fake host NIC: a dummy interface, or a TUN device read by the capture
#               (auto: dummy if the dummy driver is already loaded, otherwise tun, so the
#               run never makes the kernel load a module)
#   --keep-work keep OUT/w (product state, lab keys, logs) instead of deleting it
#
# Layout. Nothing needs root, nothing on the host changes; the host is only read (snapshots):
#
#   host                     read-only snapshots before and after (routes, rules, DNS, proxy)
#   └ harness                unshare --user --map-root-user --net --mount --pid (uid 0 inside a
#     │                      user namespace of our own: no host privilege)
#     │  lo                  WireGuard to the lab peer, API, Gateways        -> captures/lo.pcap
#     │  dummy0 (or nic0)    the only way out: default routes v4+v6, system  -> captures/nic.pcap
#     │                      resolver 192.0.2.53; it drops what it gets
#     │  private /run, /tmp, resolv.conf: no host resolver daemon, D-Bus or session socket in
#     │  reach, so a system-resolver call can only become a DNS packet on the NIC
#     └ driver               unshare --user --map-user=<you>: your uid, no capabilities in the
#        │                   harness network namespace, as in a real installation
#        │  scripts/dev-stack.sh --release --seed  (vpn-labpeer, vpnd manager and controller)
#        │  scripts/leak_scenarios.py drive        (scenarios, managed Apps, events.jsonl)
#        └ strict sandboxes (made by the product): lo + vpn0 only  -> captures/sandbox-*.pcap
#
# Scenarios (attributed by timestamps): control_pre, setup, a_baseline, c_fault_gateway,
# d_dns_down_gateway, b_strict, c_fault_strict, d_dns_down_strict, e_v6_block, teardown,
# control_post; f_host_state compares the snapshots. Pass criteria (scripts/leak_capture.py
# analyze): no packet attributable to the product on the NIC; on lo only WireGuard between the
# worker's underlay socket and the lab peer (framing checked) or loopback TCP/UDP to the
# product's own ports; payload markers nowhere else; functional checks, DNS failure within the
# deadline, IPv6 refused without an IPv6 tunnel; snapshots identical. Exit status 1 on any FAIL.
#
# Results: OUT/results/report.txt (table and details), summary.json, flows-<capture>.json,
# events.jsonl; pcaps in OUT/captures (Wireshark); logs in OUT/logs.
set -euo pipefail

SELF=$(readlink -f "$0")
SCRIPTS=$(dirname "${SELF}")

die() { echo "leak-capture: $*" >&2; exit 2; }
usage() { sed -n '2,46p' "${SELF}" | sed 's/^# \{0,1\}//'; exit 2; }

# ---------------------------------------------------------------------------------------------
# Outer: on the host, as the user
# ---------------------------------------------------------------------------------------------

host_snapshot() {
  echo "## ip route"; ip route show
  echo "## ip -6 route"; ip -6 route show | sed -E 's/ expires [0-9]+sec//'
  echo "## ip rule"; ip rule show
  echo "## ip -6 rule"; ip -6 rule show
  echo "## links (name, flags)"; ip -o link show | awk '{print $2, $3}'
  local resolv
  resolv=$(readlink -f /etc/resolv.conf) || true
  echo "## /etc/resolv.conf (${resolv})"; cat /etc/resolv.conf
  echo "## sha256"; sha256sum /etc/hosts /etc/nsswitch.conf /etc/environment 2>&1 || true
  echo "## proxy environment"; env | grep -i '_proxy=' | sort || true
  if command -v gsettings >/dev/null; then
    echo "## gsettings org.gnome.system.proxy mode"
    timeout 5 gsettings get org.gnome.system.proxy mode 2>&1 || true
  fi
  for t in nft iptables-save; do
    command -v "${t}" >/dev/null || echo "## ${t}: not installed on this host"
  done
}

outer() {
  local kernel
  kernel=$(uname -s) || true
  [[ "${kernel}" = Linux ]] || die "Linux only"
  for t in unshare nsenter ip ss python3 curl getent timeout sha256sum; do
    command -v "${t}" >/dev/null || die "missing tool: ${t}"
  done
  local devstack commit source
  if [[ -n "${SRC}" ]]; then
    if [[ "${BUILD}" = 1 ]]; then
      mkdir -p "${SRC}/target/tmp"
      (cd "${SRC}" && TMPDIR="${SRC}/target/tmp" cargo build --release -p vpnd -p vpnctl -p vpn-labpeer)
    fi
    BIN=${SRC}/target/release
    devstack=${SRC}/scripts/dev-stack.sh
    source="src ${SRC}"
    # A synced tree without .git can name its commit in .commit.
    commit=$(git -C "${SRC}" rev-parse HEAD 2>/dev/null || cat "${SRC}/.commit" 2>/dev/null \
      || echo unknown)
  elif [[ -n "${BIN}" ]]; then
    devstack=${SCRIPTS}/dev-stack.sh
    source="bin ${BIN}"
    commit=$(cat "${BIN}/.commit" 2>/dev/null || "${BIN}/vpnd" --version 2>/dev/null | head -1 \
      || echo unknown)
  else
    die "give --src DIR or --bin DIR"
  fi
  for b in vpnd vpn-labpeer; do [[ -x "${BIN}/${b}" ]] || die "missing ${BIN}/${b}"; done
  [[ -f "${devstack}" ]] || die "missing ${devstack}"

  OUT=${OUT:-${HOME}/vpnm-capture/run-$(date +%Y%m%d-%H%M%S)}
  mkdir -p "${OUT}"
  OUT=$(readlink -f "${OUT}")
  local fstype
  fstype=$(stat -f -c %T "${OUT}") || true
  [[ "${fstype}" != tmpfs ]] || die "${OUT} is on tmpfs (memory); choose a disk directory"
  [[ ! -e "${OUT}/results/events.jsonl" ]] || die "${OUT} already holds a run"
  local W=${OUT}/w
  mkdir -p "${OUT}"/{captures,results,logs,snapshots} "${W}"/{tmp,home,xdg,app,run,shim} \
    "${W}/devroot/scripts" "${W}/devroot/target"
  chmod 700 "${W}" "${W}/xdg" "${W}/home"
  # dev-stack.sh runs from a shadow root whose target/release is the binaries under test.
  cp "${devstack}" "${W}/devroot/scripts/dev-stack.sh"
  ln -sfn "${BIN}" "${W}/devroot/target/release"
  command -v uuidgen >/dev/null || {
    printf '#!/bin/sh\ncat /proc/sys/kernel/random/uuid\n' > "${W}/shim/uuidgen"
    chmod 755 "${W}/shim/uuidgen"
  }
  if [[ "${NIC}" = auto ]]; then
    if [[ -d /sys/module/dummy ]]; then NIC=dummy; else NIC=tun; fi
  fi
  case "${NIC}" in dummy|tun) ;; *) die "--nic auto|dummy|tun" ;; esac

  echo "leak-capture: ${source} (commit ${commit}), base ${BASE}, NIC ${NIC}, output ${OUT}"
  host_snapshot > "${OUT}/snapshots/host-before.txt"
  LEAK_UID=$(id -u) || true
  LEAK_GID=$(id -g)
  export LEAK_OUT="${OUT}" LEAK_BASE="${BASE}" LEAK_NIC="${NIC}" LEAK_UID LEAK_GID \
    LEAK_SOURCE="${source}" LEAK_COMMIT="${commit}" LEAK_SCRIPTS="${SCRIPTS}"
  local inner_rc=0 rc=0
  unshare --user --map-root-user --net --mount --pid --fork --mount-proc --kill-child \
    "${SELF}" --inner || inner_rc=$?
  host_snapshot > "${OUT}/snapshots/host-after.txt"
  # Product logs (no secrets by design) outlive the work directory; the lab keys do not.
  mkdir -p "${OUT}/logs/product"
  cp -p "${W}"/s/*.log "${OUT}/logs/product/" 2>/dev/null || true
  [[ ! -d "${W}/s/state/logs" ]] || cp -rp "${W}/s/state/logs" "${OUT}/logs/product/state-logs"
  python3 "${SCRIPTS}/leak_capture.py" analyze --out "${OUT}" || rc=$?
  if [[ "${KEEP}" = 1 ]]; then
    echo "work directory kept: ${W}"
  else
    rm -rf "${W}"
  fi
  echo "pcaps:     ${OUT}/captures/*.pcap"
  echo "summaries: ${OUT}/results/report.txt, summary.json, flows-*.json, events.jsonl"
  [[ "${inner_rc}" = 0 ]] || echo "leak-capture: the harness exited with ${inner_rc}" >&2
  [[ "${rc}" = 0 ]] && [[ "${inner_rc}" = 0 ]]
}

# ---------------------------------------------------------------------------------------------
# Inner: pid 1 of the harness namespaces, uid 0 of our own user namespace
# ---------------------------------------------------------------------------------------------

inner() {
  local W=${LEAK_OUT}/w caps=${LEAK_OUT}/captures nicdev n
  cd /
  # --- file system view (private mount namespace; propagation is private) ---
  mount --bind "${W}/tmp" /tmp
  # An empty /run: systemd-resolved's varlink socket, nscd, avahi, D-Bus and the user's session
  # sockets are out of reach, so no name lookup can be delegated to a host daemon unseen. The
  # system resolver is 192.0.2.53 behind the NIC.
  local resolv
  resolv=$(readlink -f /etc/resolv.conf || echo /etc/resolv.conf)
  mount --bind "${W}/run" /run
  [[ -L /var/run ]] || mount --bind "${W}/run" /var/run
  case "${resolv}" in
    /run/*|/var/run/*)
      local rel=${resolv#/run/}; rel=${rel#/var/run/}
      mkdir -p "${W}/run/$(dirname "${rel}")"
      printf 'nameserver 192.0.2.53\n' > "${W}/run/${rel}" ;;
    *)
      printf 'nameserver 192.0.2.53\n' > "${W}/resolv.conf"
      mount --bind "${W}/resolv.conf" "${resolv}" ;;
  esac

  # --- network: lo, and one fake NIC that every leak would have to use ---
  local s
  for s in default all; do
    echo 0 > "/proc/sys/net/ipv6/conf/${s}/accept_ra"
    echo 0 > "/proc/sys/net/ipv6/conf/${s}/router_solicitations"
    echo 0 > "/proc/sys/net/ipv6/conf/${s}/dad_transmits"
    echo 0 > "/proc/sys/net/ipv6/conf/${s}/autoconf"
  done
  # No link-local address on the NIC: no kernel ND/MLD/RS to tell apart from product traffic.
  echo 1 > /proc/sys/net/ipv6/conf/default/addr_gen_mode
  ip link set lo up
  python3 "${LEAK_SCRIPTS}/leak_capture.py" capture --iface lo --name lo --skip-outgoing \
    --ring-mb 128 --dir "${caps}" 2>>"${LEAK_OUT}/logs/capture-lo.log" &
  local lo_cap=$!
  local nic_cap
  if [[ "${LEAK_NIC}" = dummy ]]; then
    nicdev=dummy0
    ip link add dummy0 type dummy
    python3 "${LEAK_SCRIPTS}/leak_capture.py" capture --iface dummy0 --name nic \
      --ring-mb 16 --dir "${caps}" 2>>"${LEAK_OUT}/logs/capture-nic.log" &
    nic_cap=$!
  else
    nicdev=nic0
    # The capture creates the TUN device and reads every packet routed to it.
    python3 "${LEAK_SCRIPTS}/leak_capture.py" capture --iface nic0 --name nic --tun-nic \
      --dir "${caps}" 2>>"${LEAK_OUT}/logs/capture-nic.log" &
    nic_cap=$!
    for _ in $(seq 1 100); do ip link show nic0 >/dev/null 2>&1 && break; sleep 0.05; done
  fi
  ip link set "${nicdev}" multicast off
  ip addr add 192.0.2.2/24 dev "${nicdev}"
  ip -6 addr add 2001:db8:1::2/64 dev "${nicdev}" nodad
  ip link set "${nicdev}" up
  ip route add default via 192.0.2.1 dev "${nicdev}"
  ip -6 route add default via 2001:db8:1::1 dev "${nicdev}"
  for n in lo nic; do
    for _ in $(seq 1 100); do [[ -f "${caps}/${n}.ready" ]] && break; sleep 0.05; done
    [[ -f "${caps}/${n}.ready" ]] || { echo "capture ${n} did not start" >&2; exit 3; }
  done

  # --- the scenarios, as the user (nested user namespace: no capabilities here) ---
  local drv_rc=0 drv_user
  drv_user=$(id -un "${LEAK_UID}" 2>/dev/null || echo user)
  unshare --user --map-user="${LEAK_UID}" --map-group="${LEAK_GID}" -- \
    env -i HOME="${W}/home" TMPDIR="${W}/tmp" XDG_RUNTIME_DIR="${W}/xdg" LANG=C.UTF-8 \
    USER="${drv_user}" \
    PATH="${W}/shim:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
    python3 "${LEAK_SCRIPTS}/leak_scenarios.py" drive --out "${LEAK_OUT}" --work "${W}" \
      --devroot "${W}/devroot" --base "${LEAK_BASE}" --source "${LEAK_SOURCE}" \
      --commit "${LEAK_COMMIT}" --nic "${LEAK_NIC}" --nic-dev "${nicdev}" \
    2>&1 | tee "${LEAK_OUT}/logs/driver.log" || drv_rc=$?

  # --- wrap up: the NIC's own drop counter, stop the captures, list leftovers ---
  ip -s -j link show "${nicdev}" | python3 -c '
import json, sys, time
d = json.load(sys.stdin)[0]
s = d.get("stats64") or d.get("stats") or {}
print(json.dumps({"t": time.time(), "kind": "nic_queue_drops", "dev": d["ifname"],
                  "dropped": s.get("tx", {}).get("dropped", 0), "tx": s.get("tx", {})}))
' >> "${LEAK_OUT}/results/events.jsonl" || true
  kill -INT "${lo_cap}" "${nic_cap}" 2>/dev/null || true
  wait "${lo_cap}" "${nic_cap}" 2>/dev/null || true
  ps -eo pid,ppid,args > "${LEAK_OUT}/logs/processes-at-end.txt" 2>&1 || true
  exit "${drv_rc}"
}

ROLE=outer SRC="" BIN="" BUILD=0 BASE=28765 OUT="" NIC=auto KEEP=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --src) SRC=$(readlink -f "$2"); shift 2 ;;
    --bin) BIN=$(readlink -f "$2"); shift 2 ;;
    --build) BUILD=1; shift ;;
    --base) BASE=$2; shift 2 ;;
    --out) OUT=$2; shift 2 ;;
    --nic) NIC=$2; shift 2 ;;
    --keep-work) KEEP=1; shift ;;
    --inner) ROLE=inner; shift ;;
    -h|--help) usage ;;
    *) echo "unknown option: $1" >&2; usage ;;
  esac
done
if [[ "${ROLE}" = inner ]]; then inner; else outer; fi
