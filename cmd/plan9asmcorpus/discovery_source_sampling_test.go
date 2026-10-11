package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/llgo-compat/plan9asm/internal/gotoolchain"
)

func TestDiscoverySourceDiagnosticSamplesBoundedLocationsNotOccurrences(t *testing.T) {
	for _, count := range []int{1, 255, 256, 257, 513, 4096} {
		for _, repeated := range []bool{false, true} {
			t.Run(fmt.Sprintf("count=%d/repeated=%t", count, repeated), func(t *testing.T) {
				var output strings.Builder
				for index := 0; index < count; index++ {
					line := index + 1
					if repeated {
						line = 42
					}
					fmt.Fprintf(&output, "/source/pkg/decl.go:%d:3: undefined: sourceIdentifier\n", line)
				}
				diagnostic := output.String()
				witness := captureDiscoverySourceDiagnostic(diagnostic)
				if err := validateDiscoverySourceDiagnostic(witness); err != nil {
					t.Fatalf("concrete source occurrences exceeded compact evidence capacity: %v", err)
				}
				wantCount := count
				if repeated {
					wantCount = 1
				} else if wantCount > 256 {
					wantCount = 256
				}
				if len(witness.Locations) != wantCount {
					t.Fatalf("compact location sample=%d want=%d", len(witness.Locations), wantCount)
				}
				digest := sha256.Sum256([]byte(diagnostic))
				if witness.SHA256 != hex.EncodeToString(digest[:]) {
					t.Fatal("bounded sample changed the full raw diagnostic digest")
				}
				item := discoverySourceNotApplicableItem{Kind: discoverySourceNotApplicableGoBuild, Reason: diagnostic, Diagnostic: witness}
				if err := validateDiscoverySourceRejectionDiagnostic(item, false); err != nil {
					t.Fatal(err)
				}
				item.Reason += "\nunsampled output changed"
				if err := validateDiscoverySourceRejectionDiagnostic(item, false); err == nil {
					t.Fatal("altered unsampled raw bytes retained the earlier witness")
				}
			})
		}
	}
}

func TestDiscoverySourceDiagnosticSamplingDoesNotDiscardLateFailures(t *testing.T) {
	var output strings.Builder
	for line := 1; line <= 600; line++ {
		fmt.Fprintf(&output, "native.s:%d: invalid instruction\n", line)
	}
	bulk := output.String()
	for _, invalid := range []string{
		"go tool asm: signal: segmentation fault",
		"go build: signal: killed",
		"write cache: no space left on device",
		"verifying module: checksum mismatch\nSECURITY ERROR",
		"Get https://sum.golang.org/tile: unexpected EOF",
		"go build: captured output exceeds 8388608 bytes",
		"go build: context deadline exceeded",
		"source proof failure: changed header",
		"native.s:4294967296: invalid source line",
		"native.s:42:4294967296: invalid source column",
	} {
		for _, diagnostic := range []string{invalid + "\n" + bulk, bulk + invalid + "\n"} {
			if witness := captureDiscoverySourceDiagnostic(diagnostic); witness != nil {
				t.Fatalf("bounded sampling hid a full-diagnostic failure: %q", invalid)
			}
		}
	}
	for _, opaque := range []string{
		"asm: assembly failed\n", "unknown tool failure\n", "exit status 1\n",
		"object.o:42: invalid instruction\n", "native.s:0: invalid instruction\n",
		"native.s:not-a-line: invalid instruction\n", "native.s:42:\n",
	} {
		if captureDiscoverySourceDiagnostic(strings.Repeat(opaque, 600)) != nil {
			t.Fatalf("many opaque lines became a concrete source rejection: %q", opaque)
		}
	}
	for _, line := range []string{
		"native.s:4294967295:4294967295: invalid instruction\n",
		"native.s:1: invalid instruction", // The final line need not end in LF.
	} {
		if witness := captureDiscoverySourceDiagnostic(line); witness == nil || len(witness.Locations) != 1 {
			t.Fatalf("valid numeric/EOF boundary lost its concrete source witness: %q", line)
		}
	}
	for _, file := range []string{"native.s", "pkg/native.s", "directory with spaces/native.s", `C:\source\native.s`} {
		for _, output := range []string{
			file + ":42: unrecognized instruction \"BAD_OPCODE\"\n",
			file + ":42:3: invalid instruction\n",
			"asm: illegal combination: ADDQ AX, X0 (" + file + ":42)\n",
		} {
			if !discoveryAssemblerSourceDiagnostic(file, output) {
				t.Errorf("actual exact assembler file mapping lost: file=%q output=%q", file, output)
			}
			if discoveryAssemblerSourceDiagnostic("other.s", output) || discoveryAssemblerSourceDiagnostic("other/native.s", output) {
				t.Fatalf("source rejection spread to an unrelated file/path: %q", file)
			}
		}
		for _, unmapped := range []string{
			"other/native.s:42: invalid instruction\n",
			"asm: illegal combination: ADDQ AX, X0 (other/" + file + ":42)\n",
			"asm: invalid instruction: (other/" + file + ":42)\tADDQ AX, X0\n",
			file + ":0: invalid instruction\n",
			file + ":4294967296: invalid instruction\n",
			file + ":42:0: invalid instruction\n",
			file + ":42:4294967296: invalid instruction\n",
			file + ":42x: invalid instruction\n",
			file + ":42:\n",
			"asm: (" + file + ":42)\n",
			file + ":42: invalid instruction\ngo tool asm: panic: tool failure\n",
		} {
			if discoveryAssemblerSourceDiagnostic(file, unmapped) {
				t.Errorf("invalid/unmapped source diagnostic became file N/A: file=%q output=%q", file, unmapped)
			}
		}
	}
}

func TestDiscoverySourceDiagnosticSamplingActualGoEncoder(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "many.s")
	writeTestFile(t, file, "TEXT ·Probe(SB),$0-0\n"+strings.Repeat("MOVL R8, AX\n", 600)+"RET\n")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	env := replaceEnv(os.Environ(), map[string]string{
		"GOTOOLCHAIN": "local", "GOWORK": "off", "GOENV": "off", "GOFLAGS": "", "GOOS": "linux", "GOARCH": "386",
	})
	_, sourceFailure := runCapturedCommandOutput(ctx, dir, env, "go", "tool", "asm", "-p", "sourceoracle", "-o", filepath.Join(dir, "rejected.o"), file)
	diagnostic := discoveryCommandDiagnostic(sourceFailure)
	if sourceFailure == nil || isDiscoveryInfrastructureFailure(sourceFailure) || strings.Count(diagnostic, "invalid instruction") < 600 {
		t.Fatalf("actual Go 386 encoder did not emit the complete concrete source rejection: %v", sourceFailure)
	}
	results, err := runDiscoveryPackageChecks([]discoveryPackageGroup{{Pattern: "sourceoracle", AsmFiles: []string{"many.s"}}}, func([]string) error {
		return sourceFailure
	})
	if err != nil || len(results) != 1 || !errors.Is(results[0], sourceFailure) {
		t.Fatalf("actual many-error Go source rejected without a bounded witness: %v", err)
	}
	witness := captureDiscoverySourceDiagnostic(diagnostic)
	if witness == nil || len(witness.Locations) != 256 || witness.Locations[0].File != "many.s" || witness.Locations[0].Line != 2 {
		t.Fatalf("actual original source locations lost: %#v", witness)
	}
	root, err := gotoolchain.Root()
	if err != nil {
		t.Fatal(err)
	}
	probe, err := probeAssemblySourceForTarget(ctx, file, "linux", "386", root)
	if err != nil || !probe.conclusive || probe.accepted || strings.Count(probe.reason, "invalid instruction") != 600 || strings.Contains(probe.reason, "diagnostic truncated") {
		t.Fatalf("actual source-selection proof lost its complete Go diagnostic: result=%+v error=%v", probe, err)
	}
	// The same source is an actual successful amd64 Go object. No code executes.
	env = replaceEnv(env, map[string]string{"GOARCH": "amd64"})
	object := filepath.Join(dir, "accepted.o")
	if _, err := runCapturedCommandOutput(ctx, dir, env, "go", "tool", "asm", "-p", "sourceoracle", "-o", object, file); err != nil {
		t.Fatal("actual amd64 object control:", err)
	}
	if info, err := os.Stat(object); err != nil || info.Size() == 0 {
		t.Fatalf("accepted original Go object absent/empty: %v", err)
	}
}

func TestDiscoveryGoBuildRejectionKeepsFullRawDiagnostic(t *testing.T) {
	asm := "TEXT ·Probe(SB),4,$0-0\n" + strings.Repeat("ADDQ AX, X0\n", 600) + "RET\n"
	report, err := runFixtureCPPProductionCandidate(t, asm)
	if err != nil {
		t.Fatal("actual production candidate lost Go source rejection:", err)
	}
	if len(report.SourceNotApplicableItems) != 1 || report.SourceNotApplicableItems[0].Kind != discoverySourceNotApplicableGoBuild {
		t.Fatalf("unexpected source outcome: %#v", report.SourceNotApplicableItems)
	}
	reason := report.SourceNotApplicableItems[0].Reason
	if strings.Count(reason, "invalid instruction") < 600 || strings.Contains(reason, "... evidence truncated ...") || strings.Contains(reason, "... output truncated ...") {
		t.Fatalf("persisted raw Go source diagnostic was display-truncated: bytes=%d lines=%d", len(reason), strings.Count(reason, "invalid instruction"))
	}
	witness := captureDiscoverySourceDiagnostic(reason)
	if err := validateDiscoverySourceDiagnostic(witness); err != nil {
		t.Fatal(err)
	}
	t.Logf("actual compile-only source rejection: full raw bytes=%d compact locations=%d", len(reason), len(witness.Locations))
}
