# PR 40 migration evidence

Imported from `cpunion/plan9asm` commit
`c8724add` (the full local PR 40 repair snapshot). Only external harness code,
records, policies and supporting scripts are transferred. No translator
implementation or official Go instruction corpus is copied here.

Before removal from the source tree, every ledger file was compared byte for
byte with that snapshot. Both directories contain 257 files (manifest plus
256 JSONL shards). The scan ledger has 102,936,308 bytes; the assembly ledger
has 1,062,089 bytes. Paths, contents, index ranges, retry state and historical
assembly outcomes were not rewritten.

The transfer SHA-256 uses sorted relative POSIX paths, followed by a NUL byte
and each file's exact contents, concatenated into one hash per directory:

- `testdata/discovery/ledger`:
  `57f40b2e37d893b48f7f894a2f251a7a2114e9b5196ebff7557472499c7b79db`
- `testdata/discovery/assembly-ledger`:
  `d550d5db23d9419d552fe0d19cdf12e2d496b1be0834c442af07fd02c0b85197`

These identify the initial transfer, not future scan results. Ordinary scanner
merges may legitimately change them. No compressed data or obsolete per-run
ledger is imported. Remote scanner data not yet merged into the source snapshot
is also not claimed to have been imported.

Reports produced in the old combined repository retain their original meaning.
Schema 12 separates the harness source from the pinned translator source;
their Git revisions need not be equal. A clean translator binary must match
the pinned source checkout, and all shards must retain the same identities.
Old reports are not upgraded by editing their schema, revision or hashes.
