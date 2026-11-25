# Measured performance

One machine, one disk, Python 3.12, nothing mocked: the same `core` functions the
broker uses. Numbers are medians of one run; the point is the shape, not the third
digit.

## Append a receipt

| receipts | total | per receipt | ledger size |
|---|---|---|---|
| 250 | 5.5 s | 22.1 ms | 0.2 MB |
| 500 | 7.0 s | 14.1 ms | 0.4 MB |
| 1,000 | 12.0 s | 12.0 ms | 0.8 MB |
| 2,000 | 19.0 s | 9.5 ms | 1.6 MB |
| 10,000 | 97.3 s | 9.7 ms | 8.1 MB |

Flat per-receipt cost is the point: `append_receipt` writes the line, `fsync`s it,
and rewrites `.head`. Until 0.51.2 it also read the **whole ledger** on every
append, so the tenth thousand receipt cost a thousand times the first. The test
`tests/test_append.py` grows the ledger four times and fails if the cost grows
with it.

The ~10 ms is `fsync`, not parsing. That is the price of a receipt that survives a
power cut; batching would trade it away.

## Verify and package

| operation | 10,000 receipts |
|---|---|
| `verify_chain` (hash chain + `.head`, no anchor fetch) | **1.94 s** |
| `mandate pack` (inventory, changes, DORA row, hashes) | **0.55 s**, 6 files |

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

## One number that is not reproducible here

The Firecracker pause figure (17.2 ms, guest stopped) was measured once on
`crusoe-cpu1`, the only host we have with `/dev/kvm`; `gama-lab-fra` has no KVM, so
CI cannot re-run it. Treat it as a single-site measurement, not a benchmark, and
ask for a re-run on your own hypervisor.

