# plan9asm compatibility

Go Module Index discovery and external assembly compatibility tests for
[plan9asm](https://github.com/xgo-dev/plan9asm). This repository owns the
scanner, sharded inventory, assembly evidence, exception manifests and external
test jobs. The translator, official Go instruction-table coverage and independent
instruction regressions remain in the translator repository.

## Setup

Use Go 1.27.1, LLVM 22, Git, jq and Node.js 22. Required missing tools are errors.
`go.mod` pins the translator library; `translator.json` pins its matching source
checkout for the CLI. Until the upstream split lands, both pins use the
contribution fork. The checkout helper never updates an existing dirty or
different-version checkout.

```sh
source scripts/translator-source.sh
prepare_translator_source "$PWD"
go test ./cmd/plan9asmdiscover ./internal/... -count=1 -timeout=20m
go test ./cmd/plan9asmcorpus -count=1 -timeout=45m
node --test .github/scripts/priority-*.test.cjs
```

These are first-party harness fixtures, not a scan or external compilation run.
`PLAN9ASM_TRANSLATOR_ROOT` can select an existing matching translator checkout.

## Inventory and verification

Read [discovery operations](testdata/discovery/README.md) for the automatic
bidirectional cursors, streaming merge/deduplication, retries and byte accounting.
Use the existing ledger; do not rescan its historical ranges after migration.

```sh
go run ./cmd/plan9asmdiscover -status -out-dir testdata/discovery/ledger

# On a separate disposable compilation executor, not the inventory server:
scripts/check-reported-library-corpus.sh all
PLAN9ASM_DISCOVERY_PARALLELISM=4 scripts/check-discovered-library-corpus.sh all 128
scripts/verify-discovered-library-corpus.sh --progress
scripts/update-assembly-ledger.sh
```

See [verification rules](docs/development/discovery-verification.md) and
[validation commands](docs/development/validation.md). Scanning proves inventory;
corpus passes prove translation and LLVM object compilation, not whole-program
linking or execution. Those remain separate LLGo compatibility tests.

The imported assembly ledger is **historical and incomplete**. It is retained
byte-for-byte, not relabeled as current-head success. Fresh schema-12 reports
bind the harness and translator independently. Missing, old or partial reports
cannot pass the strict aggregate. See [migration evidence](docs/migration.md).
