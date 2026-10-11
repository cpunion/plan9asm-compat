# Validation

Use Go 1.27.1 and LLVM 22 exactly. Put the selected Go and LLVM tools on PATH;
candidate subprocesses deliberately use `GOTOOLCHAIN=local`. No LLVM fallback
or missing-tool skip is allowed. Only the translator's official tests use
historical Go versions.

Prepare the pinned translator source with `scripts/translator-source.sh` as
shown in README. Its source revision must match the library pin in go.mod.

```sh
go test ./... -count=1 -timeout=45m
go vet ./...
go build ./...
node --test .github/scripts/priority-*.test.cjs
git diff --check
```

The corpus-driver suite contains first-party producer fixtures. It may be run
exhaustively using the translator's test runner with this repository as `-dir`
and `github.com/llgo-compat/plan9asm/cmd/plan9asmcorpus` as `-package`.
Running those unit tests does not validate downloaded external modules.

## Frozen external verification

Commit first and freeze both checkouts, tools and ledgers. Run external corpus
batches on disposable remote executors, never locally or on the inventory
server. Each candidate owns and cleans its workspace; a caller-owned shared
Go build cache is not deleted by another writer.

The full gate requires all 128 schema-12 reports with exact, disjoint ownership
and identical harness/translator/ledger/tool provenance. Progress schema 3 and
assembly-ledger v3 retain file/target/profile/custom-tag scopes and actual
compiler/object receipts. A migrated historical report cannot satisfy this
gate. The strict aggregate runs even after priority failures to retain partial
diagnostics, but partial diagnostics never make it green.

Use `scripts/update-assembly-ledger.sh` only with fresh matching reports. Do not
edit pass statuses, source revisions, hashes or skip reasons by hand. The
imported historical ledger is intentionally unchanged and initially fails the
current-head verified-ledger gate. This is unfinished coverage, not a reason to
weaken the gate.

## Contribution

Push batches only to an allowed fork and create/update its contribution PR.
Keep it draft until current-head CI, review and coverage pass. Let running
frozen batches finish; preserve failures and never mix old artifacts with a new
head. Put scan/coverage funnel tables in PR bodies, with their exact denominator
and cutoff, rather than progress narratives in documentation.
