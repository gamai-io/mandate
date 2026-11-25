#!/usr/bin/env bash
# Boot a Firecracker microVM, prove it has no network, and measure pause/resume.
#
#   ./tools/firecracker_demo.sh [--kernel K] [--rootfs R]
#
# Needs /dev/kvm, the firecracker binary, a kernel and a rootfs. Set FC, KERNEL and
# ROOTFS if they live elsewhere. Prints one JSON object.
# The guest is started without any network device: that is the isolation claim.
set -euo pipefail

FC="${FC:-/opt/fc/release-v1.17.0-x86_64/firecracker-v1.17.0-x86_64}"
KERNEL="${KERNEL:-/opt/fc/vmlinux.bin}"
ROOTFS="${ROOTFS:-/var/lib/firecracker/rootfs.ext4}"
MEM="${MEM:-256}"
VCPUS="${VCPUS:-1}"
SOCK="/tmp/fc-demo-$$.sock"
LOG="/tmp/fc-demo-$$.log"
SERIAL="/tmp/fc-demo-$$.serial"
PIDFILE="/tmp/fc-demo-$$.pid"

cleanup() {
  if [[ -f "$PIDFILE" ]]; then kill "$(cat "$PIDFILE")" 2>/dev/null || true; fi
  rm -f "$SOCK" "$PIDFILE" "$SERIAL"
}
trap cleanup EXIT

fail() { printf '{"ok": false, "stage": "%s", "error": "%s"}\n' "$1" "${2:-}"; exit 1; }

[[ -e /dev/kvm ]] || fail "kvm" "/dev/kvm is missing on this host"
[[ -x "$FC" ]] || fail "binary" "$FC not found"
[[ -f "$KERNEL" ]] || fail "kernel" "$KERNEL not found"
[[ -f "$ROOTFS" ]] || fail "rootfs" "$ROOTFS not found"

api() { curl -s --unix-socket "$SOCK" "$@"; }
wait_api() {
  for _ in $(seq 1 100); do
    api -X GET http://localhost/ >/dev/null 2>&1 && return 0
    sleep 0.05
  done
  return 1
}

rm -f "$SOCK" "$LOG" "$SERIAL"

# 1. start the process, configure, then measure from InstanceStart to serial output
"$FC" --api-sock "$SOCK" --log-path "$LOG" --level Info > "$SERIAL" 2>&1 &
echo $! > "$PIDFILE"
wait_api || fail "api" "the API socket never appeared"

api -X PUT http://localhost/boot-source -H 'Content-Type: application/json' \
  -d "{\"kernel_image_path\":\"$KERNEL\",\"boot_args\":\"console=ttyS0 reboot=k panic=1 pci=off\"}" >/dev/null
api -X PUT http://localhost/machine-config -H 'Content-Type: application/json' \
  -d "{\"vcpu_count\":$VCPUS,\"mem_size_mib\":$MEM}" >/dev/null
api -X PUT http://localhost/drives/rootfs -H 'Content-Type: application/json' \
  -d "{\"drive_id\":\"rootfs\",\"path_on_host\":\"$ROOTFS\",\"is_root_device\":true,\"is_read_only\":true}" >/dev/null

start_ms=$(date +%s%3N)
api -X PUT http://localhost/actions -H 'Content-Type: application/json' \
  -d '{"action_type":"InstanceStart"}' >/dev/null

booted_ms=""
for _ in $(seq 1 200); do
  if [[ -s "$SERIAL" ]] && grep -qE "Linux version|login:|Welcome|Booting" "$SERIAL" 2>/dev/null; then
    booted_ms=$(( $(date +%s%3N) - start_ms ))
    break
  fi
  sleep 0.05
done
[[ -n "$booted_ms" ]] || fail "boot" "no kernel output within 10s"

# 2. no network device was configured for this VM, so the guest has no interface.
#    Firecracker exposes no collection to list them; the honest check is that we
#    never sent a PUT /network-interfaces and that no tap was created for it.
tap_devices=$(ip -o link show 2>/dev/null | grep -c 'tap' || true)

# 3. pause and resume through the API, measure the latency
state() { api -X GET http://localhost/ | sed -n 's/.*"state":"\([A-Za-z]*\)".*/\1/p'; }
state_before=$(state)
t0=$(date +%s%3N)
pause_code=$(api -o /dev/null -w '%{http_code}' -X PATCH http://localhost/vm \
  -H 'Content-Type: application/json' -d '{"state":"Paused"}')
pause_ms=$(( $(date +%s%3N) - t0 ))
state_paused=$(state)
t0=$(date +%s%3N)
resume_code=$(api -o /dev/null -w '%{http_code}' -X PATCH http://localhost/vm \
  -H 'Content-Type: application/json' -d '{"state":"Resumed"}')
resume_ms=$(( $(date +%s%3N) - t0 ))
state_resumed=$(state)

printf '{"ok": true, "host": "%s", "kvm": true, "vcpus": %s, "mem_mib": %s,\n' \
  "$(hostname)" "$VCPUS" "$MEM"
printf ' "boot_to_serial_ms": %s,\n' "$booted_ms"
printf ' "network_devices_configured": 0, "tap_devices_on_host": %s,\n' "$tap_devices"
printf ' "state_before": "%s", "state_paused": "%s", "state_resumed": "%s",\n' \
  "$state_before" "$state_paused" "$state_resumed"
printf ' "pause_http": %s, "resume_http": %s,\n' "$pause_code" "$resume_code"
printf ' "pause_ms": %s, "resume_ms": %s}\n' "$pause_ms" "$resume_ms"
