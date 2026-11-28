# Release log: what it proves, and what it does not

Every file we publish is a leaf in an append-only log in the shape of RFC 6962. The head is a
`size` and a `root`; a checkpoint signs that head with a log key; an RFC 3161 authority timestamps
the checkpoint. The public copies live at `gamai.io/tlog/` and the page at `gamai.io/tlog.html`
verifies inclusion **in your browser**.

```
leaf_hash(d)     = SHA-256(0x00 || d)
node_hash(l, r)  = SHA-256(0x01 || l || r)
MTH(empty)       = SHA-256("")
entry            = JCS(JSON of {release, file, sha256, bytes, uploaded, url})
```

## What it proves

1. **Inclusion**: a given artifact is in the log at index i, with a proof of `log₂(size)` hashes.
   A tampered entry fails; a proof from another index fails. Tested for every leaf at sizes 1–17,
   where the split rule actually bends.
2. **Order**: the leaf order is the publication order we claim, and any later log must have this
   log as a prefix (`mandate tlog verify` + `consistency`).
3. **Time**: the checkpoint digest is timestamped by FreeTSA (`gen_time` in `anchors.json`), so
   "this head existed at 2026-11-28T11:58:52Z" is not our word.

## What it does not prove

- **Not that we did not rewrite history before anyone looked.** A log run by one party is
  tamper-evident *relative to a checkpoint someone else kept*. If nobody kept an older copy, a
  rewrite is invisible. The mitigation is external: an RFC 3161 timestamp (done) and a mirrored
  copy by a second party (not done — say so in a questionnaire).
- **Not that a release is good.** It says the bytes we published are the bytes in the log, not
  that the code is correct or the tests are honest.
- **Not AP2/registry-level acceptance.** A registry has its own hashes; ours must agree, and
  `tools/publish_tlog.py` builds entries from PyPI's metadata precisely so that a disagreement
  would be visible.

## Commands

```bash
# build and sign a log from a manifest of entries
mandate tlog build --manifest entries.json --key log_key --signer mandate-log --out log.json
mandate tlog head --log log.json

# prove one entry and check it independently
mandate tlog prove --log log.json --index 3 --out proof.json
mandate tlog verify --entry entry.json --proof proof.json --checkpoint checkpoint.json

# timestamp the checkpoint externally (RFC 3161)
mandate tlog anchor --checkpoint checkpoint.json --out anchors/
```

## Honest limits in the output

`mandate tlog verify` returns `ok: false` with exit 4 on a bad checkpoint signature, a proof that
does not rebuild the root, or a checkpoint whose head differs from the proof's. The browser page
prints `potpis valjan` / `potpis NIJE valjan` and `eksterni pečat: nema` when no anchor covers the
current head, instead of implying one exists.
