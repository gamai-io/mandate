# Measured performance

One machine, one disk, Python 3.12, nothing mocked: the same `core` functions the
broker uses. Reproduced with `tools/bench_ledger.py` on 2026-11-26; numbers are
one run, and `fsync` makes the absolute value a property of the disk, so read the
shape rather than the third digit.

## Append a receipt

Run on 2026-11-26 by `tools/bench_ledger.py` (this host, ext4, Python 3.12):

| receipts | total | per receipt | ledger size |
|---|---|---|---|
| 250 | 1.7 s | 6.8 ms | 0.2 MB |
| 500 | 3.5 s | 6.9 ms | 0.4 MB |
| 1,000 | 8.8 s | 8.8 ms | 0.8 MB |
| 2,000 | 14.6 s | 7.3 ms | 1.6 MB |
| 10,000 | 89.0 s | 8.9 ms | 8.2 MB |

Flat per-receipt cost is the point: `append_receipt` writes the line, `fsync`s it,
and rewrites `.head`. Until 0.51.2 it also read the **whole ledger** on every
append, so the tenth thousand receipt cost a thousand times the first. The test
`tests/test_append.py` grows the ledger four times and fails if the cost grows
with it.

The per-receipt cost is `fsync`, not parsing. It depends on the disk: the same
script gave **5.75 ms** on a faster host and **9.7 ms** on the slowest one here, so
treat the figure as a range (6-10 ms), not a constant. That is the price of a
receipt that survives a power cut; batching would trade it away.

## Verify and package

| operation | 10,000 receipts |
|---|---|
| `verify_chain` (hash chain + `.head`, no anchor fetch) | **1.85 s** |
| `mandate pack` (inventory, changes, DORA row, hashes) | **0.71 s**, 7 files |

Verification is linear in the number of entries and needs no network. A bank that
keeps seven years of receipts should expect roughly 0.2 ms per receipt per
verification run and should anchor the head rather than the body.

## What these numbers do not cover

- One disk, no RAID, no network filesystem. `fsync` on a bank's SAN will differ.
- No concurrent writers beyond the file lock; `append_receipt` serialises writers
  by design, so throughput is one writer at a time.
- No measurement of the broker's full request path (HTTP, journal, provider call);
  only the ledger primitives.
- The offline verifiers (`spec/verify_offline.py`, `verify_offline.js`) were not
  benchmarked at scale; they verify one grant and one receipt at a time.

Run it yourself:

```bash
python3 tools/bench_ledger.py --count 10000
```

## MicroVM: boot, isolation and pause, reproducible

```bash
./tools/firecracker_demo.sh
```

Measured on `crusoe-cpu1` (the only host here with `/dev/kvm`), Firecracker 1.17.0,
1 vCPU, 256 MiB, read-only rootfs, **no network device configured**:

| step | result |
|---|---|
boot until the first kernel line on the serial console | **125 ms** |
network devices configured | **0** (and no tap device on the host) |
`PATCH /vm {"state":"Paused"}` → state `Paused` | **7 ms**, HTTP 204 |
`PATCH /vm {"state":"Resumed"}` → state `Running` | **6 ms**, HTTP 204 |

The earlier figure in this file (17.2 ms to halt) came from `mandate warden`, which
stops the VM and then *verifies* the state through the API before reporting; the
numbers above are the bare API round-trip. Both are single-host measurements: a
bank should re-run the script on its own hypervisor rather than trust ours.

CI cannot run this (no `/dev/kvm` in the runners); `mandate sandbox check` is the
part that runs everywhere and proves egress isolation with bubblewrap.

