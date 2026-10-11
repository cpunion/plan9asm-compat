# Go module assembly discovery ledger

`ledger/` is the repository-owned checkpoint for newest-to-oldest scans of the
official Go module index. The history pass stops at 2019-04-10. Each
`(module path, Go-semver major)` line keeps only its newest scanned version.
Thus v0 and v1 coexist even on the same path; `/v2`, `/v3`, and `gopkg.in`
`.v2`/`.v3` paths also advance independently. It records the selected
exact `module@latest` version, including modules without Plan 9 assembly.
Assembly matches retain every `.s` path and architecture hint for all current
Go ports, including architectures plan9asm does not support yet; failures
remain eligible for retry.

Results are deliberately stored as uncompressed, line-oriented JSON instead
of a binary gzip blob:

```text
ledger/
  manifest.json
  records/00.jsonl ... records/ff.jsonl
assembly-ledger/
  manifest.json
  records/00.jsonl ... records/ff.jsonl
```

`sha256(module)[0]` selects one of 256 shards, so all records for a module stay
in one stable file. Records are sorted by module, Go semantic version, and
result kind. Updating the ledger replaces obsolete versions within one line; a later
success also clears the corresponding retryable failure. Repository tests
validate the layout, shard ownership, ordering, and counts, and reject
committed `.gz` discovery results.

The scan ledger's `scanned` records include inspected versions with no
assembly; `matched` records retain assembly candidates. The separate
`assembly-ledger/` records each matched exact version as `pending`, `passed`,
`failed`, evidence-backed `not_applicable`, or a distinct audited skip
(`skipped_invalid_source`, `skipped_superseded`, or
`skipped_private_extension`). Private-extension skips identify one exact
file/target and retain successful translations of other files without counting
the module as passed. Its manifest binds the scan
fingerprint, frozen report/tool provenance and source content. It is an
audited status snapshot, not input to discovery or corpus compilation. A
change to the scanner/compiler source or scan ledger makes the snapshot
stale; updating only the evidence snapshot does not. Direct cgo-import
inventory remains outside this repository.

`pending` is an intermediate state, never completion. Before promotion,
regenerate the assembly ledger from all 128 audited reports and require
`-assembly-ledger-status ... -require-verified-assembly-ledger` to succeed.
The CI aggregate also compares that snapshot with every result in the current
128 shard reports; matching source and scan hashes alone are insufficient.
Each `passed` record retains its positive LLVM object-compilation count; each
source-inapplicable or explicit skip retains its reason and pinned evidence.
Source-inapplicable ledger details keep the affected files, targets and stable
reason category. Full Go diagnostics remain in the shard reports because they
can contain temporary runner paths and are unsuitable for committed records.
This gate does not claim llgo compilation, linking, or execution. Schema-12
reports, progress schema 3 and assembly-ledger v3 preserve ordinary
file/target/profile-ID/custom-tag scopes, shared actual Go/tool observations,
package-role selection, CPP graphs and LLVM object consumer proofs. Old reports
or ledgers cannot acquire these claims by relabeling their schema. Fresh reports
are required after integration; the existing historical snapshot is not upgraded
by these implementation changes.

Current ordinary reports additionally require the source-derived
`exact_source_instrumentation_denominator_v2` plan, even for its explicit empty
`requirements: []` set. Actual race/msan/asan exports, queries, CPP and LLVM
objects have separate mode/CGO scopes and independent readers. Their completed
object count is retained as `instrumentation_translations`. Exact registered
early target exclusions retain a separate actual tag-aware command and full
original source witness, counted only in `instrumentation_target_exclusions`.
CGO/SDK/source/consumer failures and all-excluded zero-object candidates remain
failed, not ordinary N/A or skips. Historical v1 refusals stay failed.
Deleting the plan and outcomes together cannot downgrade a mode-required source.
These objects do not claim sanitizer final linkage or runtime execution.

Concrete source-rejection witnesses sample at most the first 256 distinct
source positions, then sort that sample canonically. This is a compact evidence
bound, not a limit on valid Go diagnostics or their repeated occurrences. The
witness digest binds the complete diagnostic retained in the frozen report,
not an error-display tail or a truncated prefix. The producer still inspects
the complete command output for infrastructure failures; output exceeding its
8 MiB capture limit fails explicitly instead of becoming source N/A.
Go omits unknown columns. Explicit column fields must be positive canonical
decimal positions, not zero, signed/overflow values or empty messages; invalid
fields must not backtrack into a line-only source message.

Continue from this checkpoint without downloading completed versions again:

```sh
go run ./cmd/plan9asmdiscover \
  -limit 20000 \
  -workers 64 \
  -traffic-report _out/discovery-traffic.json \
  -out-dir testdata/discovery/ledger
```

When `-out-dir` already exists, it is validated, used as the completed
exact-version checkpoint, and updated in place. The history upper bound is
derived from the earliest `index_ranges[].since`; a new ledger starts at the
current time. Because the official index only offers an ascending `since`
API, the scanner brackets complete time windows internally and selects their
newest records. It never splits a timestamp group, so a batch may contain
slightly more than `-limit` records without making the next reverse cursor lose
entries. Every committed interval and its exact entry count is retained in
`manifest.json` under `index_ranges`. Parsed-time ordering, identical adjacent
endpoints, and aggregate entry counts are checked whenever the ledger is read
or written; gaps, overlaps, and conflicting repeats are rejected. Thus no
manual cursor copying is part of normal operation. `-seen-report` remains
available for additional legacy JSON, gzip-compressed JSON, or sharded import
sources and is repeatable. Every selected module discovered in the index is
resolved to an exact `@latest` version before ZIP inspection. A completed exact
version is reused without another ZIP request. A newly seen version line or a
higher Go semver within one line crosses its checkpoint and is resolved;
older versions of that same line do not cause metadata or ZIP traffic. If
`@latest` selects another major, the indexed exact version is inspected.
If `@latest` resolves to a newer version in the same line, the old version's
scanned, matched, and failure records are removed.
For a new exact version, Discovery uses HEAD and range requests to read the ZIP
directory and candidate `.s` contents; it does not materialize the complete
module. Only `matched` versions are downloaded through the Go module cache by
the later corpus translation/LLVM compilation stage.

`-traffic-report` writes one sorted JSON entry for every module that actually
made a request. It separates `@latest`, ZIP HEAD, ZIP range, and whole-small-ZIP
traffic, including retries, and gives per-module and run totals. Bytes mean
HTTP response entity bytes read with `Accept-Encoding: identity`; HTTP headers
and TLS/IP overhead are outside this application-level measurement. Index
traffic is reported separately because it does not belong to one module. A
module absent from the report made zero proxy requests.

List the largest modules in one batch:

```sh
jq -r '.modules[] | [.total_body_bytes, .total_requests, .module,
  .resolved_version, .outcome] | @tsv' _out/discovery-traffic.json |
  sort -nr | head -20
```

`outcome` is `scanned`, `matched`, `failure`, `reused_scanned`, or
`reused_matched`. Reused modules normally make only the `@latest` metadata
request; their previously inspected exact ZIP is not fetched again. GitHub
pseudo-versions at the same commit also share successful ZIP inspection across
repository-path case aliases, including aliases encountered concurrently in
one batch. Semantic tags and case-sensitive module subdirectories are never
folded.

`-workers` parallelizes module inspection inside one Discovery process. Ledger
publication remains single-writer and is protected by a sibling writer lock;
never launch concurrent processes targeting the same `-out-dir`, and do not
rewrite a ledger while corpus shards are reading it. Corpus shards themselves
may run in parallel because the ledger is read-only and each shard has a unique
report path.

Run an incremental head scan whenever needed; it does not depend on the history
scan having reached 2019:

```sh
go run ./cmd/plan9asmdiscover \
  -scan-mode incremental \
  -workers 64 \
  -out-dir testdata/discovery/ledger
```

Incremental mode derives its lower bound from the greatest committed
`index_ranges[].before` value and scans only up to the new current-time upper
bound. It always drains that interval and ignores `-limit`, so it cannot
publish a new high-water mark while leaving an unrecorded gap. A newly
published `/v3` is therefore processed even when `/v2` already has a
checkpoint. Empty intervals are recorded with an exact zero count so the same
head window is not fetched repeatedly. History extends the earliest range and
incremental scanning extends the latest range, preserving one continuous
coverage chain in both directions.
Changing deduplication does not rewind either cursor or reconstruct records
discarded by an older rule; only unscanned intervals are processed next.

Retry retained failures without rereading the module index:

```sh
go run ./cmd/plan9asmdiscover \
  -scan-mode retry \
  -limit 2000 \
  -workers 64 \
  -out-dir testdata/discovery/ledger
```

Retry validates the complete ledger but retains only a limit-sized selection,
not the whole failure queue. `-limit 0` uses the default 2,000-module retry
batch; a negative limit fails. The optional `retry_after` manifest field records
the last selected logical module/version key. The next batch advances after
that key and wraps around, so repeated failures cannot starve later entries.
This queue marker never advances or rewinds either index cursor.

Validate the complete ledger and print both derived endpoints plus the funnel
counts at any time without network access:

```sh
go run ./cmd/plan9asmdiscover -status \
  -out-dir testdata/discovery/ledger
```

The status read checks range continuity, the sum of range entry counts, all
manifest/record counts, shard ownership, semantic ordering, and duplicates.
It validates every shard through the same streaming scanner as the full import
reader, but retains only manifest/range metadata, shard identities, counters
and the current/previous record. Publication readback uses this summary path
too. Manifest bytes and shard generation are rechecked before returning a
summary; a concurrent replacement or ordinary input edit fails.

Normal scan startup retains only this metadata. Checkpoint lookup then streams
the complete inputs and keeps records only for the active batch's module paths
and repository case aliases. Unselected shards still receive full validation.
Publication merges one complete module at a time with the current update
batch, recomputes counts, validates the staged ledger, and atomically replaces
the previous directory under its writer lock. Memory scales with the active
batch and largest current module group, not total ledger payload.

Import a sharded ledger without a ledger-wide decode:

```sh
go run ./cmd/plan9asmdiscover \
  -convert-report _out/import-ledger \
  -out-dir testdata/discovery/ledger
```

Sharded imports validate both complete ledgers and merge two module streams
within each logical shard. They lock both inputs, reject overlapping physical
paths, and recheck input generations before publication. The full record reader
remains available for reference comparisons and explicit monolithic legacy
JSON/gzip compatibility imports; those legacy imports are not memory-bounded.

Former per-run collections (a directory with child manifests, but no root
manifest) use the same streaming converter. It preserves sorted manifest order,
folds source contributions before merging with the destination, and verifies the
complete member set before publishing. Cursor metadata scales with the number of
members; record payload scales with the current module groups, not the complete
collection. Only one cursor file is open at a time. Byte offsets permit direct
seeks: the boundary record is read twice, not earlier module groups. Every source
still receives complete initial/final EOF, ordering, count and generation checks.
Child directory symlinks remain unfollowed. Explicit monolithic JSON/gzip remains
a separate compatibility path.

After adding a new supported target, its external assembly corpus can be
replayed directly from the saved exact versions without reading the module
index or revisiting no-assembly modules:

```sh
for shard in $(seq 0 63); do
  PLAN9ASM_DISCOVERY_TARGETS=linux/riscv64 \
    scripts/check-discovered-library-corpus.sh "$shard" 64 \
    "_out/discovered-library-corpus/riscv64-shard-$shard.json"
done
```

The target filter uses the recorded file paths. It conservatively retains
unsuffixed and custom-suffixed files, then fetches only those matched exact
versions and applies the current Go source/build-constraint checks before
translation and LLVM 22 compilation.

The external-library discovery and compilation corpus uses Go 1.27 only. The
Go 1.20–1.27 matrix belongs exclusively to the separate official Go
toolchain/standard-library assembly corpus.
