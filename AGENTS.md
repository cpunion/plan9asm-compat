# External assembly compatibility

This repository owns Go Module Index discovery, scan/assembly ledgers, external
assembly compatibility tests and their CI. Instruction implementation, official
Go assembler coverage and independent lowering regressions belong upstream in
`xgo-dev/plan9asm`. Do not copy the translator here.

- Read [discovery operations](testdata/discovery/README.md) and
  [verification](docs/development/discovery-verification.md) before changing
  inventory, source applicability or evidence handling.
- Push only to a fork owned by `cpunion` or `dastai`; contribute to
  `llgo-compat/plan9asm` by PR. Do not merge or directly push upstream.
- Use Go 1.27.1 and LLVM 22. Missing required tools fail, never skip. External
  library compilation does not use the historical Go compatibility matrix.
- Run index scans on the designated remote scanner, and compile external code
  on separate disposable executors. Local first-party harness fixtures are OK.
- Never restart historical inventory during migration. Preserve contiguous
  index ranges, bidirectional cursors, retries and assembly file inventories.
  Use the scanner's locked merge writer for semantic-version deduplication;
  never concurrently edit JSONL shards by hand.
- Freeze the harness, translator, ledger and tools during validation. A changed
  input invalidates the run. Historical passes remain historical; migration
  alone does not validate any external module at the new revision.
- Keep skipped outcomes separate from passes, with exact source/tool evidence
  and reasons. Unsupported instructions and infrastructure failures are not N/A.
- Preserve failed reports; keep reports, caches and binaries under `_out/`.
  Never commit archives, compressed ledgers, private paths or hostnames.
- Add regression tests before fixes. Keep code readable, release LLVM objects
  and subprocess resources, and clean owned package caches after consumers close.
- Commit verified batches promptly. Keep contributions draft until their
  current-head tests and CI pass. No partial shard set is complete coverage.

See README for setup and commands. Inventory counts are not translation passes;
translation/object compilation is not a program link or execution certificate.
