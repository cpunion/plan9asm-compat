//go:build go1.27

package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCPPActiveGeneratedHeaderFullDefaultOriginalObjects(t *testing.T) {
	testCPPActiveGeneratedHeaderFullDefaultOriginalObjects(t,
		"package header\ntype Record struct { Value uint64 }\nfunc Probe()\n")
}

func TestCPPBuiltinUnsafeGeneratedHeaderFullDefaultOriginalObjects(t *testing.T) {
	testCPPActiveGeneratedHeaderFullDefaultOriginalObjects(t, `package header
import u "unsafe"
type Record struct { Value uint64 }
type Descriptors struct {
	Prefix byte
	Pointer u.Pointer
	Bytes []byte
	Text string
	Map map[byte]byte
	Channel chan byte
	Function func()
	Any interface{}
	Tail [0]byte
}
const Width = u.Sizeof(Descriptors{})
const Alignment = u.Alignof(Descriptors{})
const BytesOffset = u.Offsetof(Descriptors{}.Bytes)
func Probe()
`)
}

func TestCPPGenericGeneratedHeaderFullDefaultOriginalObjects(t *testing.T) {
	testCPPActiveGeneratedHeaderFullDefaultOriginalObjects(t, `package header
type Record struct { Value uint64 }
type Generic[T any] struct {
	Value T
	Tail [0]byte
}
type Concrete = Generic[uint64]
type Nested struct { Item Generic[string] }
func Identity[T any](value T) T { return value }
var InstantiatedFunction = Identity[int]
func Probe()
`)
}

func TestCPPIndependentImportGeneratedHeaderFullDefaultOriginalObjects(t *testing.T) {
	testCPPActiveGeneratedHeaderFullDefaultOriginalObjects(t, `package header
import dep "example.invalid/active-header/dependency"
type Record struct { Value uint64 }
const Value = 7
var UnusedByHeader = dep.New("initializer")
func Holder() { _ = dep.New("function body") }
func Probe()
`, map[string]string{
		"dependency/value.go": "package dependency\nfunc New(value string) string { return value }\n",
	})
}

func TestCPPOrdinaryFunctionDirectivesGeneratedHeaderFullDefaultOriginalObjects(t *testing.T) {
	testCPPActiveGeneratedHeaderFullDefaultOriginalObjects(t, `package header
import dep "example.invalid/active-header/dependency"
type Record struct { Value uint64 }
const Value = 7
var UnusedByHeader = dep.New("initializer")
//go:noinline
//go:nosplit
func Holder() uintptr { return 7 }
//go:norace
//go:nocheckptr
//go:uintptrescapes
func Identity(value uintptr) uintptr { return value }
//go:noescape
func Probe()
`, map[string]string{
		"dependency/value.go": "package dependency\nfunc New(value string) string { return value }\n",
	})
}

func testCPPActiveGeneratedHeaderFullDefaultOriginalObjects(t *testing.T, source string, extras ...map[string]string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	compilerEnv := os.Environ()
	candidate := discoveryCandidate{
		Module: "example.invalid/active-header", Version: "v1.0.0", AsmFiles: []string{"probe.s"},
	}
	sources := map[string]string{
		"go.mod":   "module example.invalid/active-header\n\ngo 1.20\n",
		"probe.go": source,
		"probe.s":  "#include \"go_asm.h\"\nTEXT ·Probe(SB),4,$0-0\nRET\nGLOBL ·recordMarker(SB),$Record__size\n",
	}
	for _, extra := range extras {
		for name, text := range extra {
			if _, duplicate := sources[name]; duplicate {
				t.Fatalf("duplicate original fixture source: %s", name)
			}
			sources[name] = text
		}
	}
	download := fixtureProfileModuleDownload(t, candidate, sources)
	installGeneratedFixtureProxy(t, candidate, download, sources["go.mod"])
	targets, err := parseDiscoveryTargets("darwin/amd64,darwin/arm64,linux/386,linux/amd64,linux/arm,linux/arm64,windows/386,windows/amd64,windows/arm64,js/wasm,wasip1/wasm")
	if err != nil {
		t.Fatal(err)
	}
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	goBinary, err = filepath.Abs(goBinary)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range targets {
		goos, goarch, _ := strings.Cut(target, "/")
		env := replaceEnv(os.Environ(), map[string]string{
			"GOOS": goos, "GOARCH": goarch, "CGO_ENABLED": "0", "GOTOOLCHAIN": "local",
			"GOENV": "off", "GOWORK": "off", "GOFLAGS": "", "GOEXPERIMENT": "",
		})
		stdout, stderr, err := runDiscoveryMachineCommand(ctx, download.Dir, env, goBinary,
			"list", "-p=2", "-mod=readonly", "-export", "-compiled", "-json", ".")
		if err != nil || len(stderr) != 0 {
			t.Fatalf("actual original Go export %s: %v\n%s\n%s", target, err, stdout, stderr)
		}
		var selected struct {
			GoFiles, CompiledGoFiles, SFiles []string
			Export                           string
		}
		if err := json.Unmarshal(stdout, &selected); err != nil || selected.Export == "" ||
			!equalDiscoveryStrings(selected.GoFiles, []string{"probe.go"}) ||
			!equalDiscoveryStrings(selected.CompiledGoFiles, []string{"probe.go"}) ||
			!equalDiscoveryStrings(selected.SFiles, []string{"probe.s"}) {
			t.Fatalf("actual original compiled-source selection: %+v %v", selected, err)
		}
		exportSHA, err := discoveryFeatureFileSHA256(selected.Export)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("ACTIVE_HEADER_ORIGINAL_EXPORT target=%s asm_sha=%s go_sha=%s export_sha=%s", target,
			discoveryFeatureBytesSHA256([]byte(sources["probe.s"])), discoveryFeatureBytesSHA256([]byte(sources["probe.go"])), exportSHA)
	}
	root, err := fixtureTranslatorRoot()
	if err != nil {
		t.Fatal(err)
	}
	translator := filepath.Join(t.TempDir(), "plan9asmll")
	if output, stderr, err := runDiscoveryMachineCommand(ctx, filepath.Join(root, "cmd", "plan9asmll"), compilerEnv,
		goBinary, "build", "-p=2", "-o", translator, "."); err != nil || len(output) != 0 || len(stderr) != 0 {
		t.Fatalf("build actual owned translator: %v\n%s\n%s", err, output, stderr)
	}
	llc, err := exec.LookPath("llc")
	if err != nil {
		t.Fatal(err)
	}
	matrix, _, configs, err := runDiscoveryCandidate(discoveryCorpusConfig{
		RepoRoot: root, Translator: translator, LLC: llc, Targets: targets, CandidateTimeout: 12 * time.Minute,
	}, candidate, filepath.Join(t.TempDir(), "candidate"))
	if err != nil {
		t.Fatalf("Go-accepted complete original full11 must reach actual consumers without speculative allCPU profiles: %v", err)
	}
	if matrix.Success != len(targets) || matrix.NotApplicable != 0 || len(configs) != len(targets) || len(matrix.FeatureConsumption) != len(targets) {
		t.Fatalf("complete actual full11 object denominator changed: objects=%d configs=%d consumers=%d NA=%d",
			matrix.Success, len(configs), len(matrix.FeatureConsumption), matrix.NotApplicable)
	}
	assertCPPHeaderPlanningActualPortable(t, candidate, matrix, configs, targets)
}
