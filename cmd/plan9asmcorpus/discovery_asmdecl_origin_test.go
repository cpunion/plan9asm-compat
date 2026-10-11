package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDiscoveryAsmDeclOriginsActualSameBasename(t *testing.T) {
	root := discoveryAsmDeclRetryPhysicalTemp(t)
	main, dependency := filepath.Join(root, "main"), filepath.Join(root, "dep")
	discoveryAsmDeclOriginSources(t, map[string]string{
		filepath.Join(main, "go.mod"):       "module example.invalid/origin-main\n\ngo 1.20\nrequire example.invalid/origin-dep v0.0.0\nreplace example.invalid/origin-dep => ../dep\n",
		filepath.Join(dependency, "go.mod"): "module example.invalid/origin-dep\n\ngo 1.20\n",
	})
	for _, pkg := range []struct{ dir, name, symbol string }{
		{main, "one", "One"}, {main, "two", "Two"}, {dependency, "two", "Foreign"},
	} {
		discoveryAsmDeclOriginSources(t, map[string]string{
			filepath.Join(pkg.dir, pkg.name, "decl.go"):      "package origin\nfunc " + pkg.symbol + "() uint64\n",
			filepath.Join(pkg.dir, pkg.name, "decl_amd64.s"): "TEXT ·" + pkg.symbol + "(SB),4,$0-8\nMOVQ $2, ret+8(FP)\nRET\n",
		})
	}
	env := discoveryAsmDeclLocalFixtureEnvironment(t)
	discoveryAsmDeclOriginToolIdentity(t, main, env)
	discoveryAsmDeclOriginSelection(t, main, env, "./one", "./two", "example.invalid/origin-dep/two")
	candidate := []string{"one/decl_amd64.s", "two/decl_amd64.s"}
	for _, test := range []struct {
		name, pattern string
		packageFiles  []string
		rejected      []string
		foreignOnly   bool
	}{
		{"own package one", "./one", candidate[:1], candidate[:1], false},
		{"same candidate sibling two", "./two", candidate[:1], nil, true},
		{"actual external module same basename", "example.invalid/origin-dep/two", candidate[:1], nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			failure := discoveryAsmDeclOriginVet(t, main, env, test.pattern)
			rejected, err := classifyDiscoveryAsmDeclFailure(main, test.packageFiles, candidate, failure)
			if len(test.rejected) != 0 {
				if err != nil || !reflect.DeepEqual(rejected, test.rejected) {
					t.Fatalf("actual own source was not exactly attributed: rejected=%v error=%v", rejected, err)
				}
			} else if err == nil || len(rejected) != 0 {
				t.Fatalf("actual other source was attributed to own package: rejected=%v error=%v", rejected, err)
			}
			if actual := discoveryAsmDeclOnlyForeignCandidateABI(main, candidate, test.packageFiles, failure); actual != test.foreignOnly {
				t.Fatalf("actual foreign-candidate classification=%t, want=%t: %v", actual, test.foreignOnly, failure)
			}
		})
	}
	t.Run("both own basenames retain independent evidence", func(t *testing.T) {
		failure := discoveryAsmDeclOriginVet(t, main, env, "./one", "./two")
		rejected, err := classifyDiscoveryAsmDeclFailure(main, candidate, candidate, failure)
		if err != nil || !reflect.DeepEqual(rejected, candidate) {
			t.Fatalf("actual two-package ABI diagnostics were conflated: %v %v", rejected, err)
		}
		proof := discoveryAsmDeclRejectionEvidence(main, failure, rejected)
		if !strings.Contains(proof, "One: invalid offset") || !strings.Contains(proof, "Two: invalid offset") {
			t.Fatalf("actual independent source evidence was lost: %s", proof)
		}
	})
	t.Run("own and external diagnostics remain a failed whole analysis", func(t *testing.T) {
		failure := discoveryAsmDeclOriginVet(t, main, env, "./one", "example.invalid/origin-dep/two")
		rejected, err := classifyDiscoveryAsmDeclFailure(main, candidate[:1], candidate, failure)
		if err == nil || len(rejected) != 0 || discoveryAsmDeclOnlyForeignCandidateABI(main, candidate, candidate[:1], failure) {
			t.Fatalf("mixed actual external diagnostic was swallowed: rejected=%v error=%v", rejected, err)
		}
	})
}

func TestDiscoveryAsmDeclOriginsActualLogicalPWD(t *testing.T) {
	root := discoveryAsmDeclRetryPhysicalTemp(t)
	main := filepath.Join(root, "physical")
	discoveryAsmDeclOriginSources(t, map[string]string{
		filepath.Join(main, "go.mod"):                   "module example.invalid/logical-origin\n\ngo 1.20\n",
		filepath.Join(main, "selected", "decl.go"):      "package origin\nfunc Value() uint64\n",
		filepath.Join(main, "selected", "decl_amd64.s"): "TEXT ·Value(SB),4,$0-8\nMOVQ $2, ret+8(FP)\nRET\n",
	})
	logical := filepath.Join(root, "logical")
	if err := os.Symlink(main, logical); err != nil {
		t.Fatalf("required first-party logical-CWD fixture: %v", err)
	}
	for _, test := range []struct{ name, cwd, pwd string }{
		{"same physical logical PWD", logical, logical},
		{"unrelated PWD cannot replace real CWD", logical, root},
	} {
		t.Run(test.name, func(t *testing.T) {
			env := replaceEnv(discoveryAsmDeclLocalFixtureEnvironment(t), map[string]string{"PWD": test.pwd})
			failure := discoveryAsmDeclOriginVet(t, test.cwd, env, "./selected")
			files := []string{"selected/decl_amd64.s"}
			rejected, err := classifyDiscoveryAsmDeclFailure(main, files, files, failure)
			if err != nil || !reflect.DeepEqual(rejected, files) {
				t.Fatalf("actual logical/physical source identity was lost: %v %v; %v", rejected, err, failure)
			}
			physical, err := filepath.EvalSymlinks(failure.directory)
			if err != nil || physical != main {
				t.Fatalf("actual command directory changed to unrelated PWD: %s %v", failure.directory, err)
			}
		})
	}
}

func TestDiscoveryAsmDeclOriginsActualTestlessAfterCleanup(t *testing.T) {
	root := discoveryAsmDeclRetryPhysicalTemp(t)
	main := filepath.Join(root, "main")
	discoveryAsmDeclOriginSources(t, map[string]string{
		filepath.Join(main, "go.mod"):                   "module example.invalid/staged-origin\n\ngo 1.20\n",
		filepath.Join(main, "selected", "decl.go"):      "package origin\nfunc Value() uint64\n",
		filepath.Join(main, "selected", "decl_amd64.s"): "TEXT ·Value(SB),4,$0-8\nMOVQ $2, ret+8(FP)\nRET\n",
		filepath.Join(main, "selected", "decl_test.go"): "package origin\nvar obsolete = missingTestIdentifier\n",
	})
	env := replaceEnv(discoveryAsmDeclLocalFixtureEnvironment(t), map[string]string{"GOCACHE": t.TempDir()})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	vetArgs := []string{"vet", "-asmdecl", "-mod=mod", "./selected"}
	_, original := runCapturedCommandOutput(ctx, main, env, "go", vetArgs...)
	discoveryAsmDeclRetryRequireActualFailure(t, original, "missingTestIdentifier")
	t.Logf("actual original tests stop analysis, CWD=%s argv=%v: %v", main, vetArgs, original)
	err := runDiscoveryAsmDeclWithTestlessModuleCopies(ctx, main, env, vetArgs, nil, []string{"./selected"})
	failure := discoveryAsmDeclOriginRequireFailure(t, err)
	if len(failure.asmdeclOrigins) != 1 {
		t.Fatalf("actual stage lacks exact original mapping: %+v", failure.asmdeclOrigins)
	}
	for stage, origin := range failure.asmdeclOrigins {
		if origin != main {
			t.Fatalf("actual stage has wrong original module identity: %s -> %s", stage, origin)
		}
		if _, err := os.Stat(stage); !os.IsNotExist(err) {
			t.Fatalf("actual owning retry did not clean its stage: %s: %v", stage, err)
		}
		t.Logf("actual cleaned stage=%s original=%s commandDir=%s diagnostic=%s", stage, origin, failure.directory, failure.output)
	}
	files := []string{"selected/decl_amd64.s"}
	rejected, err := classifyDiscoveryAsmDeclFailure(main, files, files, failure)
	if err != nil || !reflect.DeepEqual(rejected, files) {
		t.Fatalf("actual stage cleanup erased original source attribution: %v %v", rejected, err)
	}
	proof := discoveryAsmDeclRejectionEvidence(main, failure, rejected)
	if !strings.Contains(proof, "Value: invalid offset ret+8(FP); expected ret+0(FP)") {
		t.Fatalf("actual stage cleanup erased concrete original rejection evidence: %s", proof)
	}
}

func TestDiscoveryAsmDeclOriginsSyntheticPathMutations(t *testing.T) {
	root := discoveryAsmDeclRetryPhysicalTemp(t)
	main, outside := filepath.Join(root, "main"), filepath.Join(root, "outside")
	discoveryAsmDeclOriginSources(t, map[string]string{
		filepath.Join(main, "go.mod"):                      "module example.invalid/mutated-origin\n\ngo 1.20\n",
		filepath.Join(main, "selected", "decl.go"):         "package origin\nfunc Value() uint64\n",
		filepath.Join(main, "selected", "decl_amd64.s"):    "TEXT ·Value(SB),4,$0-8\nMOVQ $2, ret+8(FP)\nRET\n",
		filepath.Join(outside, "decl_amd64.s"):             "TEXT ·Value(SB),4,$0-8\nMOVQ $2, ret+8(FP)\nRET\n",
		filepath.Join(outside, "selected", "decl_amd64.s"): "TEXT ·Value(SB),4,$0-8\nMOVQ $2, ret+8(FP)\nRET\n",
	})
	actual := discoveryAsmDeclOriginVet(t, main, discoveryAsmDeclLocalFixtureEnvironment(t), "./selected")
	link := filepath.Join(main, "escaped")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(root, "synthetic-stage")
	for _, test := range []struct {
		name, cwd, reported, candidate string
		origins                        map[string]string
	}{
		{"missing command directory", "", filepath.Join(main, "selected", "decl_amd64.s"), "selected/decl_amd64.s", nil},
		{"relative command directory", ".", filepath.Join(main, "selected", "decl_amd64.s"), "selected/decl_amd64.s", nil},
		{"nonexistent absolute command directory", filepath.Join(root, "never-existed"), filepath.Join(main, "selected", "decl_amd64.s"), "selected/decl_amd64.s", nil},
		{"relative candidate escape", main, "../outside/decl_amd64.s", "../outside/decl_amd64.s", nil},
		{"candidate symlink escape", main, "escaped/decl_amd64.s", "escaped/decl_amd64.s", nil},
		{"unknown reported file", main, "unknown/decl_amd64.s", "selected/decl_amd64.s", nil},
		{"nested ambiguous stage mappings", stage, "selected/decl_amd64.s", "selected/decl_amd64.s", map[string]string{stage: main, filepath.Join(stage, "selected"): outside}},
		{"duplicate canonical stage mappings", stage, "selected/decl_amd64.s", "selected/decl_amd64.s", map[string]string{stage: main, stage + string(filepath.Separator) + ".": outside}},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Only the exit status came from actual stock Go. The path, cwd and
			// private origin-map fields below are explicit unit-tripwire mutations,
			// not a claim that Go emitted or authenticated this diagnostic.
			failure := *actual
			failure.directory, failure.asmdeclOrigins = test.cwd, test.origins
			failure.output = test.reported + ":2:1: [amd64] Value: invalid offset ret+8(FP); expected ret+0(FP)\n"
			if len(test.origins) > 1 {
				// Both possible destinations exist. Ambiguous origin maps must
				// be rejected, not resolved by random Go map iteration order.
				if resolved := discoveryAsmDeclOriginalDiagnosticFile(strings.TrimSpace(failure.output), &failure); resolved != "" {
					t.Errorf("synthetic ambiguous original source was resolved: %s", resolved)
				}
			}
			files := []string{test.candidate}
			rejected, err := classifyDiscoveryAsmDeclFailure(main, files, files, &failure)
			if err == nil || len(rejected) != 0 || discoveryAsmDeclOnlyForeignCandidateABI(main, files, files, &failure) {
				t.Fatalf("synthetic unbound path acquired source permission: rejected=%v error=%v; cwd=%s output=%s origins=%v", rejected, err, test.cwd, failure.output, test.origins)
			}
		})
	}
}

func discoveryAsmDeclOriginSources(t *testing.T, files map[string]string) {
	t.Helper()
	for name, source := range files {
		name := name
		if err := os.MkdirAll(filepath.Dir(name), 0755); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, name, source)
		want := sha256.Sum256([]byte(source))
		t.Logf("first-party original source path=%s bytes=%d SHA256=%x\n%s", name, len(source), want, source)
		t.Cleanup(func() {
			data, err := os.ReadFile(name)
			if err != nil || sha256.Sum256(data) != want {
				t.Errorf("first-party original source changed: %s: %v", name, err)
			}
		})
	}
}

func discoveryAsmDeclOriginToolIdentity(t *testing.T, cwd string, env []string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	version, err := runCapturedCommandOutput(ctx, cwd, env, "go", "version")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("actual stock-Go version=%s", strings.TrimSpace(string(version)))
	toolDir, err := runCapturedCommandOutput(ctx, cwd, env, "go", "env", "GOTOOLDIR")
	if err != nil {
		t.Fatal(err)
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{goTool, filepath.Join(strings.TrimSpace(string(toolDir)), "vet"), filepath.Join(strings.TrimSpace(string(toolDir)), "asm"), filepath.Join(strings.TrimSpace(string(toolDir)), "compile")} {
		name := name
		want := discoveryAsmDeclPathFileSHA(t, name)
		t.Logf("actual stock-Go tool path=%s SHA256=%s", name, want)
		t.Cleanup(func() {
			if got := discoveryAsmDeclPathFileSHA(t, name); got != want {
				t.Errorf("actual stock-Go tool changed: %s: %s != %s", name, got, want)
			}
		})
	}
}

func discoveryAsmDeclOriginSelection(t *testing.T, cwd string, env []string, patterns ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	args := append([]string{"list", "-json"}, patterns...)
	output, err := runCapturedCommandOutput(ctx, cwd, env, "go", args...)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	for range patterns {
		var pkg struct {
			ImportPath, Dir string
			GoFiles, SFiles []string
			Module          *struct{ Path, Version, Dir, GoMod string }
		}
		if err := decoder.Decode(&pkg); err != nil {
			t.Fatal(err)
		}
		if pkg.Module == nil || !reflect.DeepEqual(pkg.SFiles, []string{"decl_amd64.s"}) || !reflect.DeepEqual(pkg.GoFiles, []string{"decl.go"}) {
			t.Fatalf("actual Go selection differs from original fixture: %+v", pkg)
		}
		t.Logf("actual source selection CWD=%s argv=%v package=%s dir=%s module=%+v GoFiles=%v SFiles=%v", cwd, args, pkg.ImportPath, pkg.Dir, pkg.Module, pkg.GoFiles, pkg.SFiles)
	}
}

func discoveryAsmDeclOriginVet(t *testing.T, cwd string, env []string, patterns ...string) *discoveryCapturedCommandError {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	// Isolate the actual diagnostics from a prior dependency VetxOnly cache.
	env = replaceEnv(env, map[string]string{"GOCACHE": t.TempDir()})
	args := append([]string{"vet", "-asmdecl"}, patterns...)
	_, err := runCapturedCommandOutput(ctx, cwd, env, "go", args...)
	t.Logf("actual stock-Go CWD=%s argv=%v diagnostic=%v", cwd, args, err)
	return discoveryAsmDeclOriginRequireFailure(t, err)
}

func discoveryAsmDeclOriginRequireFailure(t *testing.T, err error) *discoveryCapturedCommandError {
	t.Helper()
	failure, ok := err.(*discoveryCapturedCommandError)
	if !ok {
		t.Fatalf("actual stock-Go ABI fixture did not yield a direct captured failure: %v", err)
	}
	exit, ok := failure.cause.(*exec.ExitError)
	if !ok || exit.ExitCode() != 1 || !strings.Contains(failure.output, "invalid offset ret+8(FP)") {
		t.Fatalf("actual stock-Go fixture lacks completed exit-one ABI diagnostics: %v", err)
	}
	t.Logf("actual captured directory=%s origins=%v plain ExitError=%s", failure.directory, failure.asmdeclOrigins, fmt.Sprint(exit))
	return failure
}
