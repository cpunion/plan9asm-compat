# Discovery verification and standalone inventory

Read [Discovery operations](../../testdata/discovery/README.md) for the canonical
ledger format, scan commands, version ordering, traffic accounting and cursors.
Do not hand-append JSONL: `plan9asmdiscover` validates, deduplicates, semver-sorts
and publishes records automatically.

## Inventory versus testing

`scanned` proves successful exact-version inspection, including no-assembly
results. `matched` additionally retains assembly paths. `failure` remains
retryable and does not prove absence. Retain all architecture hints for future
platform queries, not only currently supported targets.

On a disposable validation executor, optional scheduling priorities do not reduce
coverage or reuse old reports:

```sh
PLAN9ASM_DISCOVERY_PRIORITY_SHARDS=25,26,39 \
  PLAN9ASM_DISCOVERY_PARALLELISM=4 \
  scripts/check-discovered-library-corpus.sh all 128
```

The priority indices must be unique and in range. Every remaining shard runs
exactly once. A bounded worker queue starts the next shard as soon as one ends,
without waiting for slow neighbors. Each shard owns its cache; the final strict
aggregate receives the same shard count as the queue.

The standalone inventory runs outside this repository and also collects direct
cgo imports. Keep its program, cgo records, deployment settings and traffic
reports outside plan9asm. Its server inventories source only: do not compile or
execute downloaded code there. Consult that checkout's own `AGENTS.md` for
service/synchronization commands; never hard-code a host or local workspace.

The standalone scanner persists successful latest resolutions with a
conservative freshness boundary. Older history reuses them across restarts;
incremental updates, newly seen major-suffixed paths and retries remain eligible.
Resolving latest does not mark a failed ZIP inspection complete. Its assembly-
only export omits cgo and latest metadata for compatibility with this
repository's three record kinds.

## Cursors and safe publication

- Derive history from the first manifest range's start and incremental from
  the last range's end. An empty ledger starts at captured current time.
  Never invent a manual resume token.
- Reverse scans consume complete windows and retain equal-timestamp groups;
  incremental scans drain their entire captured interval. Reject gaps,
  overlaps and inconsistent repeated ranges.
- Keep the highest Go-semver version per `(module path, semver major)` line.
  v0/v1 can share a path, while `/v2` and `/v3` have distinct paths. All
  coexist; older versions within each line are skipped. Do not replay already
  committed ranges after changing this rule.
- Concurrent network workers feed one publisher. Do not start a competing
  writer, remove a live lock, or overwrite a ledger being tested.
- Remote snapshots/imports validate checksums, counts, sorting and ranges.
  The standalone CLI waits on snapshot/writer contention without discarding
  an inspected batch; integrity failures are not lock retries.

## Importing an assembly-only checkpoint

First finish current corpus runs. Validate the export without network access:

```sh
go run ./cmd/plan9asmdiscover -status -out-dir "$ASSEMBLY_LEDGER"
```

Inspect ranges and records against the committed checkpoint and keep an ignored
recovery copy. The writer merges with the existing destination under its writer
lock, retaining the highest semver per version line and rejecting discontinuous ranges.

For a validated checkpoint, the converter normalizes, merges, and atomically
publishes the destination. It is not a file-copy replacement:

```sh
go run ./cmd/plan9asmdiscover \
  -convert-report "$ASSEMBLY_LEDGER" \
  -out-dir testdata/discovery/ledger

go test ./cmd/plan9asmdiscover ./cmd/plan9asmcorpus -count=1
go run ./cmd/plan9asmdiscover -status -out-dir testdata/discovery/ledger
git diff --stat -- testdata/discovery/ledger
```

Review newly selected/retired versions and retries. Commit the normalized
checkpoint, then test every selected assembly-bearing version. Only one
manifest and 256 module-hashed JSONL shards belong in Git, never gzip/run trees.

## Applicability is evidence, not an escape hatch

Select by Go filename GOOS/GOARCH suffixes and `go/build.Context.MatchFile`.
Probe unsuffixed architecture-specific assembly with the current Go assembler.
Future-target queries conservatively retain unsuffixed/custom-suffixed paths
before reevaluating source constraints.

Custom-tag replay may prune filename-impossible partners with stock MatchFile
and harmless dummy headers, never an approximate suffix or header parser.
The original assembly baseline check precedes that pruning; all surviving
configurations retain original-byte MatchFile/import/cgo checks and exact
minimum-cardinality/lexical tag selection. This local optimization neither
changes the captured source inventory nor authorizes a selection proof.

Architecture probes have bounded output, a one-minute deadline and owned
process-group cleanup. Only a positive assembler exit with an actual source
diagnostic can exclude a target. Missing tools, killed/crashed processes,
resource errors and unknown/empty tool failures remain failures. Retain the
actual target diagnostic in both ordinary source evidence and native-layout
selection plans; do not replace it with a generic rejection message. If an
empty generated-header stub lacks constants, keep the target eligible for the
real package build rather than treating the missing layout as invalid source.

For each target/tag/package group:

1. Compile that exact package and its dependencies with current Go using
   `go list -export`, not `package/...`. This compiles Go and assembly without
   demanding an executable `main` entry point or running package initialization.
   Final linking and execution belong to the separate compatibility repository.
2. Run `go vet -asmdecl`. Only concrete argument-size/FP offset/FP width
   mismatches are ABI N/A. Generic vet errors must not hide translation.
   Equal-width whole-aggregate moves remain eligible: Go's asmdecl type-kind
   comparison can reject a 16-byte MOVOU against a 16-byte array even though
   the Go compiler accepts its layout. Such a warning is not a width mismatch;
   translation and LLVM 22 compilation must still establish the outcome.
   A zero-size warning is not conclusive when the selected source's exact
   TEXT line uses omitted arguments or the historical literal `-0` form.
   Check its selected package, physical line and symbol before filtering just
   that warning. Resolve relative diagnostic paths from the actual command's
   physical working directory and require the complete path to match an actual
   selected assembly file; matching a suffix is not source evidence. Apply the
   same binding to ABI0 tail-padding warnings. Preserve other ABI diagnostics;
   unknown source metadata fails.
   A textual RET warning for a result alias may be filtered only by the
   actual unit's independently typed ABI0 layout, bound original CPP inputs,
   and complete all-path initialized-result-byte proof. Unknown effects,
   native memory, calls and uninitialized reads remain failures. A remaining
   completed concrete ABI mismatch or RET warning cannot be cleared by removing
   test declarations in a testless retry. The alias filter does not close
   nonempty actual GOFLAGS/GOEXPERIMENT or standard-package assembler contexts;
   those keep their original failures. This narrow filter proves neither
   return-continuation safety nor translation or object success.
   Result-byte checks cover every scalar ABI0 field, not only one Go return
   value. The existing signature derivation also flattens purely numerical
   arrays/structs into such fields. Require every occupied result byte on every
   returning path; padding is not initialized storage. Pointer fields, unbound
   aggregate metadata, unknown/native effects and partial results remain
   unclosed. A complete named-offset tuple proof does not broaden the separate
   single-result textual RET-warning rule or discard its actual analyzer receipt.
3. Translate every applicable saved `.s` file and compile every result with
   LLVM 22 at `-O0`. IR is verified before `llc`, and an object must be
   generated; optimization is unnecessary for this compile-only corpus and
   costly for large generated files. Unsupported instructions, parser/LLVM
   errors and missing tools fail. Other gates retain their normal `llc` level.

Deterministic current-Go compiler/assembler rejection may be structured source
N/A for that package/target only. Network, proxy, timeout, process or filesystem
failures remain failures. Every N/A needs an allowed kind, affected files,
attempted targets and a diagnostic. Omitted `TEXT -args` is not explicit zero.

Keep regressions for test-only declarations, concrete referenced `go_asm.h`
layouts, undeclared tail-forwarding ABI inference and exact-package asmdecl.
Never accept arbitrary frame mismatches just to make historical modules pass.

Generated-header parsing, canonical emission and offline validation share a
64 MiB full-text/canonical-output byte budget, not a declaration-count cap.
Retain every constant, struct size and nonblank field offset from actual Go
and selected types. Duplicate names, unknown controls, continuations and
invalid values fail; a bounded large header is not source N/A. Import/package
graph bounds and independent source/tool/layout agreement remain unchanged.

CPP inventory records original controls, not syntax acceptance of each isolated
header. In cmd/asm, an included tokenizer's EOF resumes its parent: a final
directive can obtain its required newline from that parent, but cannot invent
one at translation-unit EOF. Preserve the original bytes/hashes and verify the
actual source graph; do not append newlines, relabel capture errors as source
N/A, or infer whole-package/runtime success from successful registration.

Go's special test-source rule applies to `_test.go`, not to assembly names
containing `_test`. A selected `probe_test.s` or `probe_test_amd64.s` can belong
to an ordinary package. Explicit ordinary profiles load non-test Go packages
and prove their actual source/module/package roles; do not reject or admit a
role from the assembly basename. The unprofiled CLI's separate test-declaration
lookup remains available, but cannot supply ordinary profile evidence.

Current producers separately bind `actual_go_signature_sources_v1` in their
stamped provenance, ordinary plan and compiler consumer. Every translated TEXT
records its actual declaration/fallback source and canonical typed layout.
When ordinary types lack a function whose original selected test source has a
bodyless declaration, the consumer independently loads the stock-Go in-package
test variant under the same target/profile/custom tags. Its original Go/ASM
selection, complete typechecked source/dependency exports, actual compiler
identity and consumed symbol/layout are retained in a shared supplemental
proof. These test Go files never become ordinary package/header inputs. A
direct same-package CALL/JMP target may reuse the same witness, but only when
that normalized, zero-offset symbol is actually consumed by the current CPP
source. Entry and callee uses are distinct; repeated uses share one declaration
and must agree on its source ABI selector, type and layout. Dynamic, file-local,
cross-package and offset/alias targets do not acquire a supplemental test role.
A foreign test package, function body, source/type/export mutation, unknown tool
or poison test fails; existing ordinary declarations do not load tests. The
reader requires exact supplemental consumption and rejects deleting either
protocol or evidence to fall back to legacy rules. Historical source snapshots
retain their old claims and cannot be promoted to this contract.

Current snapshots also stamp `actual_go_test_declaration_source_closure_v3`.
A cheap selected-test bodyless-syntax predicate may request the private
`-signature-source-query`; only actual ordinary types and parsed CPP decide
which entry/callee references remain missing. This distinct query emits no
LLVM IR/object and cannot satisfy a translation scope. An adequate ordinary
declaration does not load unrelated test exports or their dependencies.
For genuinely missing references, same-profile stock-Go test dependency
selection binds the complete ImportMap and exact module/version/source roles
before typechecking. Newly required pure-Go directories remain separate
`test_declaration_go_sources` and directory inputs, verified against the
original whole ZIP and guarded through final objects. Existing assembly
dependencies retain their original tested inventory; source-only metadata
cannot introduce another assembly scope. An already inventoried pure-Go ancestor
also needs all its Go/ASM selection headers: the producer rechecks its existing
directory entries and file hashes, then adds only missing supplemental headers,
never a duplicate directory or ordinary package role. The final consumer independently
reloads the actual test selection/export, while report, progress and ledger
readers require the exact query/source closure and consumed typed signatures.
Truncated, replaced, cross-profile or unconsumed closure metadata fails; no
test source becomes ordinary input or a generated-header witness.

Version 2 closes every actual import edge, including independent nested modules
whose paths share the candidate's prefix. Ownership comes from actual Go
Module/Dir/Replace and ImportMap, not that prefix. Separate module roots retain
exact ZIP/module h1/go.mod h1, related directory membership and original minimal
Go/ASM selection headers; the consumer independently matches its actual Go
download, source roots and pre/post exports. Local or unknown replacements remain
failures; legacy archives require the separate authenticated metadata origin
described below. External ASM is source-only evidence,
not another candidate translation or object. Standard-library roots must derive
from the reobserved driver's actual GOROOT. `unsafe` retains its builtin role and
original documentation source rather than inventing a compiled export or dropping
the edge. Roots, source bytes, proxy metadata and exports stay guarded through
final objects. Offline replay checks this frozen producer/consumer evidence;
compact headers and full-file SHA alone do not independently authenticate ZIP
content without the actual ZIP-byte comparison. Current provenance rejects
deleting the new boundary evidence or relabeling an old report.

Version 3 additionally requires an embed-source witness for every selected
package, including packages with no directives. Selected original Go bytes
bind the compact `go:embed` directives; stock Go parses their patterns, and
complete original directory membership replays the exact selected asset hashes.
The consumer independently captures the actual same-profile patterns/files
before and after typechecking and guards assets through final objects. Only the
qualified test-dependency closure may supply this test role. Ordinary metadata
uses its own complete dependency-source owner and embed witnesses, described
below; it never borrows test-role authority. Unbound embeds remain errors in
either role. Unsupported generated, cgo, symlink or
unregistered asset roles remain failures, never source N/A or extra LLVM objects.
Offline replay checks frozen producer/consumer witnesses, not standalone proof
that an arbitrary compact directive is authenticated by its recorded full SHA.

One synchronous pre/post-object guard may share identical original-root checks
across test queries only when actual root/ZIP paths and the complete source,
header, directory and metadata-origin snapshots match exactly. Every proof
still checks its own exports, actual metadata copies and origin path. Each new
guard starts empty and rechecks original bytes; differing roots or tokens cannot
reuse a result. This local work reduction is not cross-phase source evidence.

## Reports and provenance

Raw failed instrumentation diagnostics stay in the frozen shard reports under
`_out/`. The automatic progress collector retains only their failure stage,
status and complete raw diagnostic SHA-256 in the committed assembly ledger.
This display-only compaction must not change source/export/object witnesses or
turn a failure into a pass or source exclusion. Ledger readers and writers
reject uncompacted failed-command text; never hand-edit a report to remove paths.

Instrumentation ABI0 declarations that reference imported types/constants, and
ordinary mode graphs with foreign module dependencies, need the separate
`actual_go_instrumentation_type_sources_v2` original input capture.
Stock Go independently selects the complete same-mode import graph before and
after export, binding actual ImportMap edges, SDK source/tool identity and exact
same-module ZIP source bytes. Metadata and object consumers recapture that graph;
portable replay retains the required packages' complete compiled Go bytes,
file-local import aliases and whole const groups, including iota positions.
Deleting this input cannot turn a selector into a local declaration. Foreign
packages bind their actual declared Module/Version and exact versioned Replace
to an independently authenticated original ZIP, module/go.mod h1, and complete
related directory inventories. The source-only module resources use the existing
ZIP/directory verification shape; they are not supplemental test declarations,
embed permissions, or eligible assembly scopes. Readers replay ordinary source
selection under the same SDK, target, mode and custom tags, require exact consumed
resource coverage, and share finite module/directory/entry/text-byte budgets.
The CLI independently recaptures the graph and retains live original resource
guards through the final metadata/CPP/LLVM boundary. Local/unknown replacements,
generated/cgo/embed roles and unauthenticated roots remain failures. The capture
itself supplies neither LLVM objects nor new caller, pointer, native-frame or
runtime permissions.

Current producer provenance requires `instrumentation_type_source_protocol`
with the v2 value even when no imported declaration needs this capture. Removing
both that marker and a capture cannot fall back to legacy semantics. Historical
v1 reports remain evidence of their original source/tool snapshot and must be
read with that snapshot's reader; current verification does not upgrade or
rewrite them. First-party synthetic file-proxy tests without SumDB certificates
are mechanism fixtures, not authentication of external modules.

Corpus sharding uses the first eight SHA-256 bytes of `module@version`, read as
an unsigned big-endian integer modulo 128. It is independent of the 256
module-hashed ledger files. Parallel shards read one frozen ledger and write
distinct reports:

```sh
PLAN9ASM_DISCOVERY_PARALLELISM=4 \
  scripts/check-discovered-library-corpus.sh all 128
scripts/verify-discovered-library-corpus.sh _out/discovered-library-corpus
```

To replay particular exact ledger candidates, invoke `plan9asmcorpus` with
repeatable `-discovery-exact-candidate=module@version`, the normal
`-discovery-shard-count=128` and their matching `-discovery-shard-index`. Keep a
fresh report directory and pass the usual manifest, ledger, repository,
translator, LLVM and report paths. Requests must be unique current ledger
matches in that shard; reader modes and target filters reject this option.
All targets and the full candidate denominator remain unchanged. Unrequested
candidates and their partial shard stay pending; a successful focused request
is not complete or verified coverage. Candidates sharing a shard must be
requested together for one report, not combined by editing old JSON. The `all`
scheduler is unchanged; never relabel old reports with another shard count.

An optional `-discovery-events=path.jsonl` records diagnostic phase spans for
download, planning, header queries and ordinary/instrumentation consumers.
The parent directory must already exist and the destination must be new;
existing files and symlinks are not overwritten. This single-writer JSONL
journal retains only active spans and checks the complete stream through EOF
after closing its owned descriptor. Requested write, close, role or readback
failures fail the run and invalidate a produced report without hiding the
original operation error. With the option absent, the schema-12 report and
execution path are unchanged. Reader/list modes reject the option.

The single-shard script enables this with `PLAN9ASM_DISCOVERY_EVENTS=1`,
creating a new `shard-N.events.jsonl` beside its report. Both CI matrices enable
and upload it separately from the compilation report, including failed runs.
Use a fresh report path when repeating an opted-in run; existing timing files
are never overwritten. A timeout may leave an incomplete diagnostic journal;
neither its spans nor a partial compilation checkpoint satisfy completion.

Each span records its exact candidate, phase, scope, start/end and actual error.
Elapsed nanoseconds use a monotonic clock; UTC timestamps are labels and must
not be subtracted to estimate work if the wall clock moves. Nested spans overlap
and must not be summed as serial time. A completed run means only that the
original top-level operation returned normally: existing code can handle a
failed child phase, whose failed span and cause remain visible. Timings never
prove a source N/A, object, candidate pass, completed shard or ledger update;
those obligations remain in the unchanged reports and verification paths.

The `all` command replaces stale canonical reports; save evidence elsewhere
under `_out/` first when needed. Download, applicability and each target
translation/compile operation each have a 60-minute deadline. Diagnostic
override: `PLAN9ASM_DISCOVERY_CANDIDATE_TIMEOUT`. A timeout fails.
The `all` command uses a bounded refillable queue. Each corpus process creates
its own temporary shard build cache and removes it only after its consumers
close. A finished shard immediately releases its cache and worker slot; one
slow shard cannot hold up the other slots or retain their old caches. Ordinary
shard failures retain a failing exit status while the remaining queue and final
strict aggregate still run. Independently invoked shards also own temporary
build caches unless `PLAN9ASM_DISCOVERY_BUILD_CACHE` names an existing absolute
directory. That override applies only to a single-shard invocation and is never
deleted by the runner; `all` ignores it rather than sharing it across the entire
ecosystem run.

The aggregate checks exact ledger ownership/inventory and these identities:

- `selected = passed + not_applicable + skipped_invalid_source + skipped_superseded + skipped_private_extension + skipped_native_layout + failed`;
- each target's `total_asm = success + not_applicable + failed`;
- final `failed = 0`, each candidate appearing exactly once.

A passing candidate needs a successful target and no failed applicable target.
A global N/A candidate has no applicable target. Translation counts are
per-target; applicable assembly files form a unique set.

Only an exact module version with pinned source SHA-256 and independently
checked evidence can be `skipped_invalid_source`: either LLVM 22 rejects the
evaluated raw ARM64 WORD, or an AMD64 raw RIP instruction names an absent
file-local constant and Go's own assembled object places its fixed target
outside every TEXT symbol. The exception manifest is
`testdata/corpus/invalid-machine-code.json`. The runner downloads the exact
version into a disposable workspace and rechecks every witness. A changed
file, decodable ARM64 word, missing constant proof or required tool fails the
candidate; a skip
never contributes to passed candidates or translation counts. Reports and
the assembly ledger retain the reason and witnesses; progress and aggregate
verification compare them with the current pinned manifest.

An obsolete exact mirror/fork may instead be `skipped_superseded` when the
reviewed `testdata/corpus/superseded-modules.json` pins its replacement module
and a strictly newer version already recorded as scanned. Evidence links must
establish project identity, not just a similar name. The runner does not
download or translate the old version; the report and assembly ledger retain
its reason and replacement. This is not a pass. If the replacement has
assembly, it remains a separate corpus candidate and must pass the same gate.

`skipped_private_extension` is a file/target exception, not a module-wide
translation exemption. The reviewed `testdata/corpus/private-extensions.json`
pins an exact source SHA-256, raw opcode, target and source link. The runner
requires current Go to assemble that file, excludes only the pinned
file/target from LLVM translation, and still compiles all other applicable
files. Its successful translations are retained, but the module is counted
as skipped rather than passed. A changed file, failed Go assembly or failed
other translation makes the candidate fail.

`skipped_native_layout` is reserved for byte-exact native TEXT/JIT behavior,
not a missing instruction form. This is a provisional Draft PR proposal, not
an accepted coverage policy. `testdata/corpus/native-layout.json` pins the
exact module version, source file, every selected target, source SHA-256,
symbol, Go object bytes and reviewable evidence. The runner reassembles the
file with current Go for each target, checks the byte witness inside that
symbol, and compiles every other applicable file. The candidate is never
counted as passed; an unpinned target, stale source, changed object bytes or
failed remaining translation fails the candidate.

Schema 9 retains a native-only pre-filter source-selection plan, captured
before exception filtering. It covers every discovered file with its source
hash, Go source/constraint-header inputs, and every report target's selected
tags or explicit exclusion. Verification replays Go filename/build-constraint
selection, checks the original plan against that selection and the full report
matrix, applies only the exact pinned file/targets, and requires each remaining
(file, target, tags) to be executed or covered by structured source N/A evidence.
Duplicate, omitted or added scopes and forged empty remainder counts fail.
The audited assembly ledger retains and revalidates the same proof; old native
reports without it cannot be promoted.

Ordinary source exclusions require `ordinary_selection_plan`. Current runs use
`exact_source_matchfile_v2`, whose `tested_asm_files` closes the immutable
Discovery inventory over all nonzero-byte `.s` siblings in those exact package
directories. Readers independently derive this canonical union from complete
ZIP-bound directory/source hashes before replaying target/profile/tag selection.
They never add unrelated packages or change `discovered_asm_files`. Zero-byte
siblings remain actual Go-selection inputs without gaining translation counts;
nonempty comments, whitespace and macro-empty sources require their own CPP,
actual Go symbol-free object/listing and LLVM object proofs. Explicit translator
file scopes cannot inject a file absent from Go's actual selected source set.
Historical `exact_source_matchfile_v1` retains its original inventory-only scope;
it cannot claim or be relabeled as v2 sibling coverage.

Current ordinary plans also require `instrumentation_plan` with protocol
`exact_source_instrumentation_denominator_v4`, including `requirements: []`
when independently replayed Go/assembly constraints require no mode. Readers
derive every race/msan/asan scope from the original source pairs, target,
custom tags and CPU/experiment request. CGO=1 is the default scope; constraints
that explicitly admit CGO=0 retain a separate scope. Mode flags are real Go
compiler flags, never custom build tags. Missing plans, null/shortened scopes,
or paired deletion of plans and outcomes fail instead of becoming ordinary N/A.

Each required mode has its own actual tool/source/environment observation,
full original compiled-Go source inventory, metadata/header query, raw CPP
registration and LLVM22 object consumer. These shared inventories are not
ordinary export evidence. An `official_target_excluded` scope requires the
separate `actual_go_instrumentation_tagged_target_exclusion_v1` witness: complete
stock-Go source registrations and actual driver/subtool bytes, target, mode,
CGO and overrides, exact canonical custom-tag argv, exit 2, empty stdout and
the unique independently replayed early diagnostic. Full original Go/ASM bytes
bind the same ZIP, directory, source-pair and tag requirement; collecting these
bytes is not Go package selection, an export, a query or an LLVM object.
`instrumentation_target_exclusions` counts these scopes separately, without
adding ordinary N/A, skip or translation credit. Missing CGO/SDK, mixed or
unknown diagnostics, source/export errors and unclosed native/generated-source
contexts remain failures. All eligible scopes still require the complete
query/CPP/object chain. All-excluded zero-object candidates remain failed;
no scope-only success policy is authorized. Queries or markers alone cannot
satisfy a scope.

A v4 `original_source_rejected` outcome is limited to complete, independently
replayed package-scope Go redeclarations. Its
`original_instrumented_package_redeclaration_v1` proof binds every selected
original source and physical declaration position to the same-mode original
compiler's plain exit 1, complete selected-package JSON and complete diagnostic.
Const, var, type and non-method function names share the package namespace;
blank names, init functions, methods and locals do not. Line directives,
additional diagnostics, missing dependencies, transport errors and timeouts
cannot satisfy this proof. Exact module setup precedes the unchanged guard;
the invocation uses its canonical owned CWD. Source roots, metadata, configs,
tools and source registrations are checked after the actual command.
This outcome grants no export, query, LLVM object or runtime credit. Its source
remains registered in the mode CPP inventory, but is not counted as a compiled
file. Every other eligible scope still requires its normal object proof. A
candidate with only rejected source and no compiled object remains failed,
including the zero-ordinary-configuration entry point and portable report,
progress and ledger readers. Earlier denominator protocols require their
frozen readers; do not relabel their evidence or copy their statuses into v4.

Mode LLVM object consumption uses `actual_go_instrumentation_llvm_objects_v3`
with mandatory `generated_artifacts` and explicit source-emission role records.
TEXT (including TEXT+DATA), DATA/GLOBL-only, and symbol-free selected siblings
are distinct roles. Symbol-free includes an actually selected zero-byte source;
it is not a zero-byte allowance or a source exclusion. The same-mode original
assembler must produce a nonempty object and an empty listing for symbol-free,
or a complete non-TEXT data-symbol listing matching every translated global
for data-only. These witnesses bind the original source, target, mode profile,
package, actual Go version and assembler bytes; ordinary observations cannot
substitute. Every selected eligible sibling still needs its own LLVM object.
Generated IR and object
outputs have distinct finite limits: 256 MiB per IR, 64 MiB per object and
1 GiB across one invocation. Canonical regular files are streamed and guarded
by exact ordinal, role, byte count and SHA-256 before final physical readback.
These are output-artifact budgets, not enlarged Go/CPP/module-source limits.
Source/type/export/CPP and actual LLVM22 compilation proofs remain mandatory;
queries or uncompiled files receive no object credit. Deleting the role pair
or restoring the older consumption protocol fails. Historical v1/v2 evidence
must use its frozen reader and cannot acquire the new source-role contract.

Mode consumers retain a different declared namespace only from complete
original ZIP `go.mod`
bytes bound to its registered member SHA. The actual version replacement,
archive path/version and canonical package namespace must agree in graph,
metadata, CPP and object consumers. Missing/changed alias metadata and proxy
metadata pretending to be that ZIP member fail; this grants no source exclusion.

The mode's complete ZIP-bound CPP graph separately derives
`cpp_feature_requirements`. Its finite assembler-CPU branch-side grammar is
shared with ordinary planning, but source selection retains the real mode and
CGO setting. Each additional CPU request needs its own actual same-mode
export, query and LLVM objects; the combined denominator is bounded to 256
scopes. Readers independently rederive the union and reject deleting a branch
along with its outcome and translation count. Unbound experiment package roles
and unknown CPU macros still fail, never become fixed-false baseline coverage.

Marker exports use `actual_go_instrumentation_marker_export_v2` and routing
v2. Their exact full command trace includes source-derived changed-CPU prefixes
on all three compiler/assembler commands. Four audited whole Go 1.27.1 driver
digests and ten complete AST projections bind the routing model; actual
bootstrap defaults and SDK `go.env` bytes/presence are rechecked before and
after export. The same hash-addressed observation is shared across scopes.
No arbitrary environment prefix or diagnostic is stripped. Early observation
v2 binds explicit `GOENV=off` to the actual empty configuration-file query;
original exports and all mode metadata/header/analyzer/object consumers retain
that policy. SDK `go.env` remains active and is not confused with user config.

Reports, progress and ledger readers
revalidate this same denominator and count completed mode object scopes in
`instrumentation_translations`, separately from ordinary scopes; successful
candidate totals include both. The proof establishes objects, not final
sanitizer linkage or runtime. Current provenance also requires the v3
instrumentation scope marker: deleting it or reverting the plan cannot
downgrade a stamped producer. Historical v1 early refusals remain failures and
old v1/v2 reports cannot acquire exclusions or CPU coverage by relabeling.

Schema-10 reports and ledger-v2 snapshots remain historical evidence. Current
verify/status/comparison entrypoints reject them as stale protocols; that
rejection is not a reclassification of any old candidate. Query historical
status with the reader source/tool version bound to that snapshot's original
provenance and semantic source fingerprint, using a separate read-only source
checkout. Do not mix historical and current reports or use the historical
reader to assert current-head completion. The v3 writer requires a fresh
destination rather than silently replacing a v2 evidence directory. Retain
the old snapshot before deliberately publishing a new, independently audited
one; no historical result or object is copied into the new denominator.

The plan captures de-duplicated source SHA-256 and actual
constraint/package-clause inputs, complete package/ancestor directory names,
the exact module ZIP SHA-256 and Go h1 identity, and every target/tag decision.
Related directory files (including assembly headers) also retain byte hashes;
the producer rechecks them after package checks before releasing its workspace.
Compiler/assembler/asmdecl source rejection requires a concrete source
diagnostic, not merely a positive exit or an assembler failure footer. Unknown
diagnostics remain failures for investigation. Raw reports keep the actual
diagnostic; compact ledger summaries retain `concrete_go_source_diagnostic_v1`
with its digest and canonical basename/line/column locations, without machine
paths or arbitrary diagnostic text. This witness depends on frozen producer
provenance; a digest alone does not authenticate report bytes. Old reason-only
ledger skips cannot be promoted by inventing a witness. Selection and
empty-object proofs remain separate from failed compiler invocations.
New ordinary runs additionally capture compact `cpp_inputs` before their Go
checks: exact ZIP-bound assembly/header SHA-256, registered CPP controls and
Go's fixed package-directory/tool-include search. Go export/vet checks and
translation recheck those inputs; changed nested headers, newly preferred
headers and source-proof errors fail, even alongside a native source error.
Shared headers outside selected Go package directories retain their separate
ZIP-bound CPP resource hashes. Their bytes may be consumed without inventing
Go package membership; actual selected Go/assembly sources still require that
membership proof, and conflicting resource/source snapshots fail closed.
Relative tool includes follow that same fixed search: for example,
`../../src/runtime/go_tls.h` from `GOROOT/pkg/include` has canonical
`tool/src/runtime/go_tls.h` identity. An escaping preferred package candidate
must have the structural `actual_go_fixed_include_search_miss_v1` witness,
derived from its original literal operand and rechecked as absent before and
after compiler phases. An existing, redirected or inaccessible outside-module
candidate fails; it is never read or silently replaced. The canonical tool
source remains regular, within actual GOROOT and byte-bound. Producer, CPP
consumer and portable readers retain the exact search witness, not a reason
string or an expanded include root.
Canonicalize the actual module/package CWD before a parent-relative search;
lexical parents of a symlink root do not describe Go's physical CWD. Active
consumption independently derives the required miss from its real include
parent and operand, even if the canonical fallback retains `pkg/include/`.
Unconsumed source literals cannot substitute for that parent. Validate the
exact module/tool origin and regular path before opening or reading bytes.
Literal authentication retains a final quoted operand at included-file EOF;
it does not supply a newline or accept directive syntax. Actual Go and active
CPP input stacks must independently accept the original graph. Translation-unit
EOF without the required newline remains rejected, with original bytes intact.
Unbound generated includes, unsupported control expansion, include cycles and
explicit inventory bounds remain failures, not empty-object N/A. This source
guard alone does not establish feature-profile or branch coverage. Historical
schema-9 reports remain historical evidence and cannot be relabeled as
schema-12 profile-aware reporting; source-diagnostic checks separately reject
reason-only rejections. CPP-only CPU predicates propose legal profiles
and require actual Go-driver observations; exclusive assembler macros are not
cumulative build tags. The producer first observes source-tag profiles and
captures their selected CPP file union, then observes CPP-required profiles.
Each ordinary `(file, target, profile ID, custom tags)` scope must have either a
concrete source diagnostic or same-profile Go export/vet, actual package-role
selection, exact CPP graph and LLVM object consumption. Progress schema 3 and
assembly-ledger v3 preserve these scopes and a canonical shared observation
inventory. Missing scope dimensions or consumer proofs fail closed. Unknown
CPU macros and experiment predicates
without an actual package-role binding fail closed. Reachable predicate sides
do not by themselves prove complete operand-form or runtime coverage.
Current producers stamp `original_always_documentation_role_v1` in both the
source plan and provenance. A documentation-only directory is excluded before
CPP registration only when its complete original inventory contains at least
one nonhidden, non-test Go file and every such file has a valid
`package documentation` clause. Actual same-driver/target/profile/custom-tag
queries must have empty GoFiles/CgoFiles, complete IgnoredGoFiles and real
SFiles, and only the registered typed Go NoGoError. Selected ordinary test
files, bad source, dependency errors, infrastructure failures and missing tools
cannot supply this witness. Both stock Go ignore paths and their header/index
and NoGoError conversion source files are bound and rechecked. Readers derive
all required scopes and selection lists from the shared ZIP-bound inventory;
missing/replaced sources, rule bytes, scopes or protocol fields fail closed.
This is scoped no-current-package evidence with zero assembly objects, not an
invalid-assembly pass or a module-wide exception. Unstamped historical
source-only replay retains its original semantics.

An unknown first CPP control may be excluded only when the current Go assembler
rejects that same original file, physical line and directive under every selected
target/profile/custom-tag scope. `pre_cpp_rejections` retains the bounded original
control prefix (64 KiB), complete actual package Go/assembly source roles, CPU
definitions, observed tool identity and exact assembler invocation/diagnostic.
Readers replay the prefix and the complete excluded-scope set; producers also
bind its bytes to the original ZIP and guard them through final checks. Earlier
includes, conditionals, definitions, lexical errors, missing generated constants
and infrastructure failures cannot use this route. Other eligible files still
require their normal CPP and compiler/object evidence. This is target-scoped
source rejection, not translation success or a module-wide exception.
An ordinary package rejected by Go's CGO=0 Fortran loader has a separate
`original_cgo0_fortran_loader_rejection_v1` proof, not a guessed source position.
It binds the complete original directory and every Go-recognized FF resource
(`.f`, `.F`, `.for`, `.f90`), selection headers, actual package Go/assembly roles,
current target/profile/custom tags, CGO=0 with no cgo/SWIG or dependency errors,
and the complete unique non-`-e` export rejection (exit 1 and empty stdout).
Readers independently replay FF filename/constraint selection and the exact
excluded scope set; the pinned Go 1.27.1 loader/build source registrations are
also checked. Missing proofs, mixed diagnostics and infrastructure failures
remain failures. Original ZIP/resource/header/tool guards run before and after
each phase. This route does not erase pre-CPP rejection attribution or bypass
unknown CPP, headers, other packages or normal eligible object scopes. Older
non-profile reports cannot use the new proof, and source N/A is never a pass.
Every package-local custom-tag configuration also includes its shared assembly
files selected by Go MatchFile. A file tested with baseline declarations is not
evidence for declarations selected by another tag configuration. Do not spread
one package's custom tags to unrelated packages or discard shared-file asmdecl
diagnostics to make the scope denominator fit.
Go also selects zero-byte `.s` siblings which Discovery does not inventory.
Capture their original ZIP-bound hashes and selection headers with the actual
package source roles. Such a sibling is accepted only with the exact empty-byte
SHA-256 and an empty selection header; it does not add a CPP translation or
LLVM output. Whitespace, comments and macro-empty nonzero files remain required
translation scopes and cannot use this allowance. Missing hashes, changed
original bytes and unregistered nonempty selected assembly fail closed.
Source-only test imports retain that exact-zero selection role outside ordinary
assembly package directories: every SFile must have the original directory
member, two matching empty-byte hashes and a present empty header. Their actual
Go selection is preserved; no LLVM object or pass count is added.
Ordinary profiles are noninstrumented: Go partner constraints impossible with
`race`, `msan` and `asan` false do not propose profiles for otherwise ordinary
assembly. Boolean/custom/CPU alternatives and negations remain selectable.
Assembly requiring instrumentation still fails until an actual driver profile
and its source/tool/consumer contract exist; these flags are never custom tags
and instrumentation-only assembly is not an ordinary N/A exemption.
Special/test-only roles, unproved generated headers, incompatible include
binding, no-TEXT profile variants without actual empty-object evidence, and
legacy modules lacking authenticated declared-module metadata remain failures.
The private `plan9asmll -metadata-only -feature-profile ... -report ...` query
uses a separate `actual_go_cpu_profile_metadata_v2` result: it performs no
assembly translation and cannot satisfy a translation PASS or add to counts.
It loads selected Go source and same-profile actual dependency exports, then
invokes the observed Go compiler with `-asmhdr`. Every definition name, value
and presence must match the selected-types emitter, not only referenced offsets.
The compact `actual_go_asmhdr_full_definitions_v1` witness retains package/source
roles, language/target/profile identity, complete ImportMap and dependency source
and export hashes, actual header/object hashes and canonical full definitions.
Offline replay relies on frozen producer provenance; production compares
the actual compiler bytes and full definitions independently. Metadata queries
alone never discharge a translation scope.

Metadata v2 requires an `actual_go_ordinary_dependency_sources_v1` owner for the
complete ordinary dependency import closure. Every selected package carries an
explicit empty or populated embed witness. Actual source selection, directives,
directory membership and asset hashes must agree before and after typechecking;
the independent consumer repeats these observations before final LLVM objects.
Candidate sources bind to the original ZIP; foreign versioned modules bind to
their exact Module/Replace identity, ZIP and original or authenticated proxy
`go.mod`; standard-library sources bind to the observed GOROOT. Pure source and
embed-selection algorithms are shared with test dependencies, not their role
permissions. Root-package embeds and instrumentation do not gain new authority.
The producer independently verifies original bytes and retains live guards
through final objects. Identical complete snapshots and physical root/ZIP/mod
paths may share one retained guard, but every capture and phase still verifies
the original inputs. Missing owners, incomplete closures and metadata v1 are
rejected by current readers; historical reports require their frozen tools.
Source-only evidence adds no translation PASS or object count.

Successful planning-only queries retain those same private live guards in the
surviving plan, even when an import or asset is absent from every final object
scope. Cached header replay and later execution phases recheck these inputs;
neither a temporary query-plan copy nor mutable report projections may replace
the original dependency owner.

Actual Go/download roots may use ancestor aliases (for example a system
temporary-directory spelling). Both producer and consumer retain the observed
root-to-canonical-root identity through their live guards. Inventories still
verify canonical roots and reject source-internal redirects; replacing an
observed alias with a different directory is not accepted even for equal bytes.

Generated-header planning privately retains cost-only negative source preflights
for one candidate operation, keyed by the complete requested profile, assembly
file and custom tags. Retention is bounded to 4,096 entries and 16 MiB of keys
and serialized observations; exceeding the bound simply performs fresh work.
Every reuse rechecks complete original source/ZIP bytes, source selection and
language, plus the SDK and owned workspace before and after the attempt. It
grants no header, profile, object or N/A credit. A now-supported source domain
requires a fresh actual tool observation and query; final executed profiles
always retain their independent actual producer checks. Ordinary errors are not
cached. Cancellation, changed-input and source-close failures stay fatal even
when the source model also reports an unsupported domain.

An explicit consumer input may register this metadata for a later translation.
That consumer independently reloads the same source/profile/import roles and
recompiles the full header before translating; self-consistent changed JSON is
not accepted. Effective header bytes use deterministic full definitions, with
an explicit `generated/<package>/go_asm.h` CPP origin rather than ZIP/tool origin.
Active includes use source-order Go package-directory search; inactive includes
do not enter the consumption graph. Discovery's deferred-source protocol retains
every raw include/condition, including unresolved inactive edges. Raw registration
and actual-profile selection must converge within eight iterations. Registration
converges on the monotonic union of original candidate roots; a shrinking selected
set does not erase raw controls or consume the iteration bound. Final eligible
file/target/profile/tag scopes independently determine translation counts. Unknown
generated presence cannot hide nested CPU conditions: bounded legal proposals
are observed before per-package headers decide actual consumption. After actual
Go export/asmdecl checks, each executed package/file/target/profile/tag scope with
a generated origin records a metadata query and independently consumes it.
Same-module imported Go inputs are hashed before loading, compared with the exact
original ZIP, and guarded through final objects. Reports and ledger replay reject
missing, duplicate, changed or unexecuted metadata scopes; no header is an empty
stub and no query increases translation counts.

One planning invocation may reuse pure parse and condition-free lexical results
keyed by complete original text and filename. Each of the two private maps is bounded to
512 entries and 64 MiB; it is neither serialized nor shared across invocations.
Eviction only affects cost. Every query still checks current public projections,
the complete source graph, generated-header roles and cancellation. Do not cache
those validation results or remove CPU/source-pair proposals. Retain mutation,
eviction, concurrent-isolation and allocation regressions when changing this path.
JSON-restored reports use that same invocation-owned parser index for resource
registration, active replay and condition-free queries. Each query owns fresh
source maps and still validates every public projection and graph relationship.
Immutable text may share backing bytes, never a caller's mutable string pointer
or directive slice. No private index is serialized into reports or the ledger.

Macro-only and inactive CPP variants may produce a symbol-free LLVM object only
after the actual Go assembler accepts the original source, creates a nonempty
object, and emits an empty `-S` symbol/data listing under the same target,
package and registered CPU definitions. CPP proofs retain an explicit emission
kind and a separate source/profile/Go/tool/object/listing witness. Invalid source,
nonempty native listings and missing LLVM outputs fail; this is not N/A. Go's
`nm` deliberately exits nonzero for an object with no symbols, so the proof uses
the assembler's successful listing instead of interpreting arbitrary tool errors.
Selected DATA/GLOBL-only sources are distinct from both TEXT and symbol-free
sources. Under the current signature protocol they require an explicit
`data_only` emission and `actual_go_data_only_symbol_listing_v1` witness.
The original same-profile Go assembler must produce a nonempty object and a
complete listing containing only recognized data/BSS/TLS symbol kinds, data
bytes and relocations. Its complete global names, static roles and sizes must
match the parsed translated GLOBL inventory. The compact native symbol
inventory and original listing/object hashes retain exact source, package,
profile and tool identity; frozen producer provenance remains mandatory.
No TEXT signature is invented, no source is marked N/A, and every scope still
requires its normal LLVM object. Missing proofs, TEXT or unknown native records,
changed global roles and signature-protocol downgrades fail closed.
Missing-signature preflight preserves that same native source role for every
DATA-only sibling before returning query metadata. Its Go object/listing witness
is not an LLVM output or a translation count. Final test-declaration consumption
requires unchanged normalized CPP and the same complete native data/symbol-free
identity as the query, including object/listing hashes and symbol inventory.
If an exact ZIP has no `go.mod`, the ordinary producer may use Go's canonical
proxy-generated module directive. This is separate `proxy_go_mod` evidence,
never an added ZIP member: exact ZIP and GoMod h1 sums, metadata bytes/SHA-256,
the public SumDB-signed tree and exact record inclusion are verified by producer,
compiler consumer and offline ledger readers. The actual download metadata path
and actual package metadata origin are checked before and after loading; changed
files, missing authentication or noncanonical synthesized directives fail.
Checksum metadata reads are bounded and read-only (or fetched in memory from
the official service), with no cache mutation. Cross-host comparison first
authenticates both checkpoints and retains their exact record/metadata identity.
An explicitly configured local `file://` module proxy may also supply cached
SumDB lookups and tiles. Cache hits remain untrusted until the public signature
and exact Merkle inclusion are checked. Malformed cache entries fail instead of
being hidden by another cache or network fallback. Each candidate owns its
`GOPATH` as well as module/build caches, including SumDB checkpoint writes.
Foreign test dependencies use the same authenticated metadata contract under
`actual_go_test_dependency_module_sources_v2`. Each module root and actual
source-only package retains its mandatory `go_mod_origin`: original ZIP bytes
or the separately signed legacy proxy role. The latter requires the complete
actual archive to lack `go.mod` and binds actual `Module.GoMod` to the exact
download metadata outside the source tree, with byte/path checks before and
after consumption. Every observed original-metadata copy retains its own
canonical-path and byte guard through final objects. Neither origin adds
external assembly objects. Missing or unknown roles, deleted signatures and
invented ZIP members fail; offline replay
retains frozen producer provenance rather than authenticating source membership
from hashes alone. Older source-root protocols cannot be relabeled.
`no_current_go_package` describes ordinary non-test source pairing only; it
does not prove that `go list -test` could not select a test-only package.
The producer checks captured files and directory names against that ZIP;
aggregate/progress/ledger readers replay MatchFile and the custom-tag search.
Offline readers validate frozen producer/source/tool provenance; they do not
independently authenticate ZIP contents without obtaining that ZIP. Header
and full-file hashes alone are not an offline cryptographic membership proof.
Every ordinary PASS and N/A must carry this proof, even when no source rejection
is recorded. Only an active verified exception uses its separate proof protocol.
Every eligible scope must have an executed configuration or a concrete scoped
source diagnostic; omissions, duplicates, changed headers and reason-only N/A
fail. The virtual root `.` is a package directory, not a hidden-directory skip.
When a concrete per-file asmdecl rejection leaves valid siblings, the consumer
retains the complete actual Go-selected package assembly registration separately
from its translated files. That registration is replayed from original hashes,
headers and the same profile/custom tags and must match actual package selection;
it never replaces an output or source diagnostic. Partial-package proofs without
this explicit registration, hidden siblings or missing diagnostics fail closed.
Reasons distinguish filename targets, disabled-cgo selection, constraints,
package-clause absence, source diagnostics and explicit target ABI evidence.
`no_current_go_package` describes the ordinary non-test Go/ASM pairing scope;
it does not prove that `go list -test` cannot select a test-only assembly package.
Ignored directories and nested modules explicitly identify recursive corpus
walk boundaries, not a claim that Go cannot build an explicitly named package.
`go_invalid_package_import_path` separately records Go's `CheckImportPath`
rejection of an exact module-relative directory, such as a bundled
`pkg/mod/example.com/library@v1.2.3` cache. Its ZIP-bound directory inventory
and diagnostic are replayed by the readers. Valid sibling packages remain
eligible; this does not relax source diagnostics or exclude instructions.
Raw diagnostics remain in reports; the ledger keeps stable source-skip categories
and compact selection inputs, never compressed third-party source archives.

The Go object witnesses establish byte-layout dependence, not runtime success.
GopherJRE's fixed +73 entry is stale on Go 1.27.1 Linux/amd64 (+63), and Sharkie's
Run+7 lands inside a CALL displacement after Go's four-byte prologue. GoJIT's
sentinel entry and fixed private frame assumptions also require runtime review.
These defects do not justify skipping ordinary instructions or other files.

Schema 10 binds Git revision/content/dirty state, full ledger fingerprint,
translator bytes/VCS metadata, matching Go build/runtime versions and LLVM 22
version/llc bytes. Before/after capture detects mutations. All shards need
identical provenance. Dirty builds are diagnostic-only; schema-2, stale tools,
mixed revisions or missing reports cannot pass. Resolve CLI repository/tool
paths before candidate working-directory changes.
GitHub PR merge and branch revisions may differ while their complete tracked
source trees are identical. The importer accepts that exact content hash match;
the translator must still match the revision recorded in its own report.

Reports prove translation/object compilation, not execution of every external
library's own test suite. Required runtime oracles remain separate.

## Progress without false completion

Query the frozen ledger and available shard reports, including a run with no
reports yet:

```sh
bash scripts/discovery-status.sh [reports-directory] [shard-count]
```

The defaults are `_out/discovered-library-corpus` and 64. `scan-status.json`
contains validated contiguous index endpoints and scan counts.
`assembly-progress.json` binds the ledger/source and lists every selected exact
version as `pending`, `passed`, `not_applicable`, `skipped_invalid_source`,
`skipped_superseded`, `skipped_private_extension`, `skipped_native_layout` or
`failed`. Its invariant
includes every one of those categories exactly once. Missing whole shards
remain pending, including in-progress shards not yet published.

The progress reader and final passing gate share the same provenance, inventory,
target and accounting checks. Stale/mixed reports or a truncated shard fail the
query instead of silently becoming coverage. `complete` means all shards and
candidates are accounted for; only `verified` additionally requires no failures.
Status-query success is not test success: the final verifier still exits
nonzero for failures or missing reports. CI publishes this view even when a
shard fails. Reports are atomically published for concurrent status readers.

CI uses `scripts/verify-discovered-library-corpus.sh --progress` on a fresh
reports directory. One full audit produces progress, applies the strict
completion gate, and compares the committed ledger; it does not audit the same
reports again just to display progress. Before any directory or file write,
the script uses the exclusive, read-only `-discovery-progress-directory` mode
to resolve physical aliases and reject either input ledger, its descendants
or ancestors. Repository output must use ignored `_out/` storage; external
output directories remain supported. The optional CLI
`-discovery-progress-output` publishes a new `assembly-progress.json` atomically.
It prepares and closes the complete temporary file first, then checks the
source, scan fingerprint and committed-ledger physical inventory before linking.
Physical record bytes stream through bounded extent-plus-one reads, not another
semantic audit or an in-memory ledger. Changed inputs invalidate publication;
cleanup never removes a foreign replacement. Status and progress publication
both refuse a destination that appeared during verification, including a directory.
Incomplete/failed candidates and ledger mismatches still exit nonzero. Malformed
or stale reports produce no progress output. Existing outputs are not replaced;
retain them and select a fresh report directory. A saved progress file cannot
replace a future audit or make a missing shard pass.

Final assembly coverage has only two accepted outcomes: tested `passed`, or
an explained skip. `not_applicable` is a source/target skip, not a pass; the
other `skipped_*` statuses retain their specific reviewed reason and witnesses.
`pending` and `failed` must remain visible during development and prevent
completion. The completion gate validates each candidate's evidence, not just
the summary's `verified` flag. Every selected assembly-bearing version must
appear exactly once, including skipped versions.

Windows publication coordinates local readers and retries transient sharing/
deletion errors for at most two seconds; persistent errors still fail and keep
the previous complete report. The required Windows job runs these concurrent
publication and external-reader regressions before the full suite.

Long shard jobs publish a partial report before the first candidate, every
eight completed candidates, and after any candidate finishes at least one
minute after the previous checkpoint. This records a slow completed candidate
before the next candidate starts; it does not credit an in-progress candidate.
A runner cancellation can therefore leave
auditable passed/failed/N/A results instead of losing the entire shard.
Partial reports mark all unreported candidates and the shard itself pending;
they never satisfy the complete-coverage gate. Publication remains atomic,
and each checkpoint rechecks the frozen source, ledger and tool provenance.

Keep test evidence separate from immutable scan records: writing a pass flag
into the hashed input ledger would invalidate that report's own provenance.
Assembly-ledger files are excluded from the source-content and dirty-worktree
fingerprints because they are derived output. To publish progress while shards
run, use a separate worktree at the same source revision for the evidence
update; leave the runner worktree and its Go binaries untouched. Do not change
the source revision or scan ledger during a shard run. After auditing the frozen
reports, publish the
diff-friendly assembly status snapshot with `scripts/update-assembly-ledger.sh`.
It writes `testdata/discovery/assembly-ledger/manifest.json` and module-hashed
JSONL shards, then reads them back against the current scan and semantic
source fingerprints. Statuses include pending and failed; `verified=true`
requires complete shard coverage and zero failures. Do not promote the
snapshot to a current pass after source or scan-ledger changes. cgo scan
records remain in the separate inventory, never in this repository.

The aggregate script logs `directory-preflight`, `scan-ledger` and `report-audit`
start/end markers, elapsed seconds and actual exits on stderr. These identify a
slow phase without contaminating canonical-path or JSON stdout. A completed
phase is diagnostic information, not a successful corpus or ledger certificate.

CI compares two independently verified snapshots semantically, not by physical
host tool or output-object bytes. Each original retains its exact LLVM version
and tool hash. The comparison preserves Go versions, the verified LLVM 22 major
contract, target/profile environment, registered sources/ASTs, marker/tag selection,
module/source/package role, CPP inputs and consumed macros, all four scope
dimensions, source-diagnostic kinds/positions and exact outcomes/counts. Profile
IDs are rebound to those retained semantics. Native-layout source/decision and
exception witnesses remain exact; only host ToolTags unreferenced by every
saved source constraint are ignored. This private projection is not evidence
and cannot pass a report reader. Within one run, shards still require identical
complete physical provenance. Old reports cannot be upgraded by relabeling.
Generated-header comparison retains full definition names/values/presence,
selected Go and dependency sources, ImportMap, language and package roles.
Only independently verified compile/header/object and dependency-export byte
hashes are projected out; producer and consumer exports remain bound within
each original snapshot. The projection never repairs missing metadata.

## Traffic and cleanup

Positionless mixed-package loader errors use a distinct typed source proof,
not a fabricated line diagnostic or an assembly pass. The producer binds the
complete original non-e export error to the actual downloaded directory,
then stores module-relative names. Readers replay sorted complete directory
entries, original import-selection headers and Go/Test/XTest/Ignored/Invalid/S
roles against the observed target/profile/custom tags. Both Go's indexed
module-cache loader and fallback source rules are registered. An incomplete
proof, unmodeled cgo role, malformed header, dependency or infrastructure error
remains a failure. Every valid sibling still requires its usual Go/CPP/LLVM
consumer and object evidence; compact progress/ledger readers preserve the
same complete scopes and typed facts.

Inspection reads ZIP metadata/ranges and candidate sources; only matched
versions are materialized for corpus tests. Successful exact versions avoid
repeat ZIP inspection. ZIPs up to 64 KiB are fetched whole; larger ZIPs start
with the 22-byte EOCD and exact directory ranges, with 64 KiB read-ahead.
Larger EOCD scans are fallbacks. Change thresholds only with measured evidence.

The corpus uses the shared Go download cache as a read-only file proxy. New
downloads, extracted sources and LLVM outputs live in a private candidate cache
removed on success or failure. Owned build caches last one shard, including
within the bounded `all` worker queue described above. Keep diagnostics, not
full packages. Replaying
an uncached exact version can download
it again; that is distinct from repeated inventory work.
Each buildable Go package is translated in its own child process. This keeps
large multi-package modules from accumulating LLVM objects across packages;
the exact version is downloaded once and candidate-level file/target counts
are still aggregated and validated. Target outputs are removed after each
successful package compilation.
Public module fetches ignore the user's global Git URL rewrites and disable
interactive Git credential prompts. A failed direct fallback remains a failure
to retry, never proof that assembly is inapplicable.
Git automatic maintenance stays in the foreground. On Unix, each captured
command owns a process group; cancellation and ordinary parent exit terminate
remaining descendants before workspace removal. Output-pipe waits are bounded
and failures remain infrastructure errors. Darwin can return `EPERM` for a
zombie-only group: only after the owned parent is actually waited may a bounded,
independent kernel snapshot prove that group absent or entirely zombie.
Darwin reads `kern.proc.pgrp` directly, including all group UIDs and no-TTY
members, with a live `kern.proc.pid` observer witness before and after the
group query. Reads are single-attempt: process-table growth, truncated/oversized
records, changed identities, unknown states or elapsed-budget errors fail.
No shell, `ps` Mach task queries, unbounded retry or command fallback is used.
Live, inaccessible, malformed or unknown owned membership still fails; a
cancellation before Wait never suppresses a permission error.
Directory-not-empty cleanup races
receive at most 20 attempts over two seconds; persistent errors fail the
candidate rather than claiming successful cleanup.

Traffic counts response-body bytes with identity encoding, not headers/TLS/IP
overhead, separating index, latest, ZIP HEAD/range and whole-ZIP requests. Do
not attribute every speedup to deduplication without accounting for changing
numbers and sizes of newly encountered modules.
