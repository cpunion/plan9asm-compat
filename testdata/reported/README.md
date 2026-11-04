# Reported assembly / ABI regressions

These are end-to-end regression probes. Every build, symbol check and execution
must pass; a failure is never an expected failure, skip or passing ledger entry.
Run on Linux/amd64 with Go 1.27.3 and LLGo built against LLVM 22:

```sh
LLGO=/path/to/llgo bash scripts/check-reported-runtime.sh
```

Pass case names to prioritize a reproduction without running the other cases:

```sh
LLGO=/path/to/llgo bash scripts/check-reported-runtime.sh s2
LLGO=/path/to/llgo bash scripts/check-reported-runtime.sh gohex purego-latest
```

`gohex`, `s2`, `purego-latest` and `turso` keep the public API programs used to reproduce
the reported failures, with exact unreplaced dependency versions. Their checks
require the Go assembler's original TEXT definitions and matching final binary
symbols. GoHex requires actual AVX or SSE4.1; scalar fallback is a failure for
this probe. S2 uses encoder size boundaries and independently constructed
literal/overlapping output-copy blocks. Purego's latest probe tests integer,
floating and mixed register/stack arguments plus a captured callback across GC.
Its small C oracle is compiled once with clang-22. Both compilers build each
program once, and every mode must execute with identical Go/LLGo output.
These probes do not establish CGO-disabled or all-platform compatibility.

The script runs every reproduction with both Go and LLGo, retains build/run
logs and a phase-specific result in a fresh `_out/reported-runtime/run.*`
directory, releases generated binaries after hashing, and fails if **any**
build or execution fails. For one case:

```sh
cd testdata/reported/sqlite # or purego / funcval
go run -mod=readonly .
llgo run .
```

`sqlite` pins libc to the version in llgo#2691 and executes a real database
query, not just the lazy `sql.Open`. `funcval` isolates its generated Go
function-pointer representation assumption without any assembly. `purego`
uses the version in llgo#2707 and performs a foreign call. `turso` pins the
actual driver and embedded native library to v0.8.3, with purego v0.9.1. It
opens a temporary database, executes Ping, CREATE, parameterized INSERT,
SELECT and rollback, checks the results, and closes the database. Its embedded
Linux/amd64 library requires glibc 2.35 or newer. The runner owns and removes
the extracted library cache, and checks the original syscall15X/callbackasm1
TEXT bodies and callbackasm code-address alias. This covers the exercised
database operations, not every Turso API, callback shape or platform.

At LLGo `0eedddd038dd78580bbd5296b85cbd6aa1164126`, Go builds of these probes
run successfully. SQLite links with LLGo but fails in mutex initialization;
the reduced function-value example has an 8-byte gc value and a 16-byte LLGo
value and also fails at invocation. Purego fails during assembly translation.
These failures remain outside the successful runtime report and must not be
inferred to pass from a green unit-test suite or the smaller ABI0 probe.

`crc32` and `libcabi0` retain the two original reported programs as independent
nested modules. Both require original assembly definitions and exact final
linked bodies: Go's ABI0 entries and LLGo's unsuffixed entries remain separate.
CRC32's main program compares custom/IEEE/Castagnoli results to an independent
bitwise oracle across length and alignment boundaries. Its main also requires
SSE4.1, SSE4.2 and PCLMULQDQ; a generic fallback is not a runtime pass. It does
not certify AVX512 execution. The libc program checks real Uint128 input,
carry, overflow, output-pointer and float32/float64 copysign wrapper paths,
not all libc callbacks. All nine programs use the same runtime runner without
copying the earlier root Go harness or treating corpus objects as executions.
