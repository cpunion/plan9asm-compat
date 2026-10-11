package main

import (
	"context"
	"errors"
	"fmt"
	"go/build"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/llgo-compat/plan9asm/internal/gotoolchain"
)

func TestAssemblyArchitectureProbeInfrastructureCannotBecomeSourceNA(t *testing.T) {
	toolDir := buildDiscoveryAssemblerProbeGoTool(t)
	t.Setenv("PATH", toolDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	file := filepath.Join(t.TempDir(), "routine.s")
	writeTestFile(t, file, "TEXT ·routine(SB), $0-0\nRET\n")
	ctx := build.Default
	ctx.GOOS, ctx.GOARCH = "linux", "amd64"

	for _, mode := range []string{
		"killed", "segfault", "memory", "permission", "unknown", "empty", "overflow", "header_then_killed", "source_then_memory",
	} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("PLAN9ASM_TEST_ASSEMBLER_PROBE_MODE", mode)
			eligible, restricted, reason, err := inferUnsuffixedAssemblyTargetsDetailed(file, []build.Context{ctx})
			if err == nil {
				t.Fatalf("tool failure became source selection: eligible=%v restricted=%v reason=%q", eligible, restricted, reason)
			}
			if reason != "" {
				t.Fatalf("tool failure also emitted source N/A evidence: %q", reason)
			}
			if mode == "overflow" && !strings.Contains(err.Error(), "captured output exceeds") {
				t.Fatalf("output overflow lost its diagnostic: %v", err)
			}
		})
	}
}

func TestAssemblyArchitectureProbeMissingGeneratedConstantsStayVisible(t *testing.T) {
	file := filepath.Join(t.TempDir(), "routine.s")
	writeTestFile(t, file, "#include \"go_asm.h\"\nTEXT ·routine(SB), $0-0\nMOVQ $const_AssemblyValue, AX\nRET\n")
	ctx := build.Default
	ctx.GOOS, ctx.GOARCH = "linux", "amd64"
	eligible, restricted, reason, err := inferUnsuffixedAssemblyTargetsDetailed(file, []build.Context{ctx})
	if err != nil {
		t.Fatal(err)
	}
	if restricted || reason != "" {
		t.Fatalf("missing generated constant hid potentially valid assembly: eligible=%v restricted=%v reason=%q", eligible, restricted, reason)
	}
}

func TestAssemblyArchitectureProbeCanceledAndMissingToolsFail(t *testing.T) {
	file := filepath.Join(t.TempDir(), "routine.s")
	writeTestFile(t, file, "TEXT ·routine(SB), $0-0\nRET\n")
	root, err := gotoolchain.Root()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := probeAssemblySourceForTarget(ctx, file, "linux", "amd64", root)
	if !errors.Is(err, context.Canceled) || result.conclusive {
		t.Fatalf("canceled probe became source evidence: result=%+v error=%v", result, err)
	}

	t.Setenv("PATH", t.TempDir())
	result, err = probeAssemblySourceForTarget(context.Background(), file, "linux", "amd64", root)
	if err == nil || result.conclusive {
		t.Fatalf("missing tool became source evidence: result=%+v error=%v", result, err)
	}
}

func TestDiscoveryEmptyGoToolFailureCannotBecomePackageNA(t *testing.T) {
	toolDir := buildDiscoveryAssemblerProbeGoTool(t)
	t.Setenv("PATH", toolDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PLAN9ASM_TEST_ASSEMBLER_PROBE_MODE", "empty")
	_, err := runCapturedCommandOutput(context.Background(), "", os.Environ(), "go", "tool", "asm")
	if err == nil || !isDiscoveryInfrastructureFailure(err) {
		t.Fatalf("empty actual process failure became source evidence: %v", err)
	}
}

func TestAssemblyArchitectureProbeRetainsTargetRejectionDiagnostic(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "package.go"), "package fixture\n")
	writeTestFile(t, filepath.Join(dir, "routine.s"), "TEXT ·routine(SB), $0-0\nMOVQ AX, AX\nRET\n")
	candidate := discoveryCandidate{Module: "example.com/fixture", Version: "v1.0.0", AsmFiles: []string{"routine.s"}}

	for _, native := range []bool{false, true} {
		t.Run(fmt.Sprintf("native=%t", native), func(t *testing.T) {
			var evidence []discoverySourceNotApplicableItem
			var plans []*discoveryNativeLayoutPlan
			if native {
				plans = append(plans, &discoveryNativeLayoutPlan{})
			}
			configs, err := discoveryBuildConfigurationsWithEvidence(candidate, dir,
				[]string{"linux/amd64", "linux/arm64"}, &evidence, plans...)
			if err != nil {
				t.Fatal(err)
			}
			if len(configs) != 1 || len(evidence) != 1 {
				t.Fatalf("configs=%v source evidence=%v; want AMD64 configuration and ARM64 rejection", configs, evidence)
			}
			if !strings.Contains(evidence[0].Reason, "routine.s:") || !strings.Contains(evidence[0].Reason, "MOVQ") {
				t.Fatalf("actual Go rejection diagnostic was lost: %q", evidence[0].Reason)
			}
			if strings.Contains(evidence[0].Reason, dir) {
				t.Fatalf("persisted reason contains disposable workspace: %q", evidence[0].Reason)
			}
			if native {
				for _, decision := range plans[0].Selections[0].Decisions {
					if decision.Kind == nativeLayoutGoAssemblerTarget && decision.Reason != evidence[0].Reason {
						t.Fatalf("native plan and source evidence disagree: %v / %v", decision, evidence[0])
					}
				}
			}
		})
	}
}

// Build a real executable rather than a shell wrapper, so the regressions also
// exercise Windows process errors. Only the assembler invocation is replaced;
// other Go commands retain the actual toolchain used to build this test.
func buildDiscoveryAssemblerProbeGoTool(t *testing.T) string {
	t.Helper()
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "probe.go")
	program := `package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
)

func main() {
	if len(os.Args) < 3 || os.Args[1] != "tool" || os.Args[2] != "asm" {
		cmd := exec.Command(` + fmt.Sprintf("%q", realGo) + `, os.Args[1:]...)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		cmd.Env = os.Environ()
		if err := cmd.Run(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	mode := os.Getenv("PLAN9ASM_TEST_ASSEMBLER_PROBE_MODE")
	if mode == "header_then_killed" {
		includes := 0
		for _, arg := range os.Args[3:] {
			if arg == "-I" {
				includes++
			}
		}
		if includes == 2 {
			fmt.Fprintln(os.Stderr, "go_asm.h: no such file or directory")
			os.Exit(1)
		}
		mode = "killed"
	}
	switch mode {
	case "killed":
		fmt.Fprintln(os.Stderr, "go tool asm: signal: killed")
	case "segfault":
		fmt.Fprintln(os.Stderr, "go tool asm: signal: segmentation fault")
	case "memory":
		fmt.Fprintln(os.Stderr, "runtime: out of memory")
	case "source_then_memory":
		fmt.Fprintf(os.Stderr, "%s:2: unrecognized instruction FOO\n", os.Args[len(os.Args)-1])
		fmt.Fprintln(os.Stderr, "runtime: out of memory")
	case "permission":
		fmt.Fprintln(os.Stderr, "go tool asm: permission denied")
	case "unknown":
		fmt.Fprintln(os.Stderr, "go tool asm: unexpected internal failure")
	case "overflow":
		os.Stderr.Write(bytes.Repeat([]byte{'x'}, (8 << 20) + 1))
	case "empty":
	default:
		fmt.Fprintln(os.Stderr, "unexpected test mode", mode)
	}
	os.Exit(1)
}
`
	writeTestFile(t, source, program)
	name := "go"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	command := exec.Command(realGo, "build", "-o", filepath.Join(dir, name), source)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build assembler-probe helper: %v\n%s", err, output)
	}
	return dir
}
