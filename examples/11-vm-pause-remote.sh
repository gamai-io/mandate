#!/usr/bin/env bash
# Find a KVM host in the fleet and prove VM pause there with the published package.
#
#   ./examples/11-vm-pause-remote.sh
#
# Requires: gama CLI (fleet), and a host with Firecracker assets. We prepare them
# once (Alpine rootfs + firecracker from /opt/fc); script is idempotent.
set -euo pipefail

NODES=${NODES:-"crusoe-cpu1"}   # extend: NODES="a b c" ./examples/11-vm-pause-remote.sh

echo "1) probing for /dev/kvm"
KVM_NODE=""
for n in $NODES; do
  out=$(timeout 25 gama hc "$n" shell "test -e /dev/kvm && echo kvm-yes || echo kvm-no" 2>/dev/null | tr -d '\n' | tail -c 20)
  case "$out" in
    *kvm-yes*) echo "   $n: KVM"; KVM_NODE=$n; break ;;
    *)         echo "   $n: no KVM" ;;
  esac
done
[ -n "$KVM_NODE" ] || { echo "no KVM host found in: $NODES"; exit 1; }
echo "   -> using $KVM_NODE"

echo "2) preparing Firecracker + rootfs on $KVM_NODE (idempotent)"
timeout 300 gama hc "$KVM_NODE" shell "set -e
cd \$HOME
mkdir -p fcwork && cd fcwork
[ -f alpine.tgz ] || curl -sL -o alpine.tgz https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-minirootfs-3.20.3-x86_64.tar.gz
if [ ! -f rootfs.ext4 ]; then
  rm -rf rootfs && mkdir rootfs && tar xzf alpine.tgz -C rootfs
  printf '#!/bin/sh\\nmount -t proc proc /proc 2>/dev/null\\necho BOOTED > /dev/console\\ni=0\\nwhile true; do i=\$((i+1)); echo tick \$i > /dev/console; sleep 0.2; done\\n' > rootfs/init
  chmod +x rootfs/init
  dd if=/dev/zero of=rootfs.ext4 bs=1M count=96 status=none
  mkfs.ext4 -q -F -d rootfs rootfs.ext4
fi
[ -d \$HOME/mv ] || python3 -m venv \$HOME/mv
\$HOME/mv/bin/pip -q install --upgrade gama-mandate
\$HOME/mv/bin/mandate version | tr -d '\\n'; echo" 2>&1 | tail -3

echo "3) starting the microVM if needed"
timeout 180 gama hc "$KVM_NODE" shell "cd \$HOME/fcwork
FC=/opt/fc/release-v1.17.0-x86_64/firecracker-v1.17.0-x86_64
if [ ! -S fc.sock ]; then
  rm -f fc.out fc.err
  (setsid nohup \$FC --api-sock \$PWD/fc.sock --id demo > fc.out 2> fc.err < /dev/null &)
  sleep 2
  curl -s -X PUT --unix-socket fc.sock http://localhost/boot-source -d '{\"kernel_image_path\":\"/opt/fc/vmlinux.bin\",\"boot_args\":\"console=ttyS0 reboot=k panic=1 pci=off init=/init\"}' >/dev/null
  curl -s -X PUT --unix-socket fc.sock http://localhost/drives/rootfs -d '{\"drive_id\":\"rootfs\",\"path_on_host\":\"'\"\$PWD\"'/rootfs.ext4\",\"is_root_device\":true,\"is_read_only\":false}' >/dev/null
  curl -s -X PUT --unix-socket fc.sock http://localhost/machine-config -d '{\"vcpu_count\":1,\"mem_size_mib\":256}' >/dev/null
  curl -s -X PUT --unix-socket fc.sock http://localhost/actions -d '{\"action_type\":\"InstanceStart\"}' >/dev/null
  sleep 3
fi
tail -1 fc.out" 2>&1 | tail -2

echo "4) pause the microVM with the published package and prove the guest stopped"
timeout 180 gama hc "$KVM_NODE" shell "cd \$HOME/fcwork
M=\$HOME/mv/bin/mandate
\$M warden --method vm-resume --vm-socket \$PWD/fc.sock --ledger ledger.jsonl --reason 'ensure running' --actor ops >/dev/null 2>&1 || true
before=\$(grep -c tick fc.out)
\$M warden --method vm-pause --vm-socket \$PWD/fc.sock --ledger ledger.jsonl --reason 'runaway agent in microVM' --actor ops > pause.json
python3 - <<'PY'
import json
d=json.load(open('pause.json'))
print('   state_before=%s state_after=%s verified=%s time_to_halt_ms=%s'
      % (d['state_before'], d['state_after'], d['verified'], d['time_to_halt_ms']))
assert d['verified'] is True and d['state_after'] == 'Paused'
PY
sleep 3
after=\$(grep -c tick fc.out)
echo \"   ticks before=\$before after 3s=\$after\"
[ \"\$before\" = \"\$after\" ] || { echo '   FAIL: guest kept running while paused'; exit 1; }
\$M warden --method vm-resume --vm-socket \$PWD/fc.sock --ledger ledger.jsonl --reason 'restore' --actor ops | grep -E 'verified' | sed 's/^/   resume /'
\$M chain --ledger ledger.jsonl | tr -d '\\n'; echo" 2>&1 | tail -10

echo
echo "OK: KVM host $KVM_NODE, guest frozen in the kernel, evidence in the ledger."
