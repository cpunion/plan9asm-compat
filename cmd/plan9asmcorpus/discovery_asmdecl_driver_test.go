package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDiscoveryAsmDeclDirectSameCacheRunsDiagnosticsTwice(t *testing.T) {
	root := discoveryAsmDeclRetryPhysicalTemp(t)
	mainDir := filepath.Join(root, "main")
	depDir := filepath.Join(root, "dep")
	for _, dir := range []string{mainDir, depDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	writeTestFile(t, filepath.Join(mainDir, "go.mod"),
		"module example.invalid/direct-main\n\ngo 1.20\n\nrequire example.invalid/direct-dep v0.0.0\nreplace example.invalid/direct-dep => ../dep\n")
	writeTestFile(t, filepath.Join(mainDir, "main.go"),
		"package main\nimport _ \"example.invalid/direct-dep\"\n")
	writeTestFile(t, filepath.Join(depDir, "go.mod"), "module example.invalid/direct-dep\n\ngo 1.20\n")
	writeTestFile(t, filepath.Join(depDir, "decl.go"), "package dep\nfunc Bad() uint64\n")
	writeTestFile(t, filepath.Join(depDir, "decl_amd64.s"),
		"TEXT ·Bad(SB),4,$0-8\nMOVQ $2, ret+8(FP)\nRET\n")
	env := discoveryAsmDeclDirectFixtureEnv(t, root)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	first, err := runCapturedCommandOutput(ctx, mainDir, env, "go", "vet", "-x", "-asmdecl", ".")
	if err != nil || !strings.Contains(string(first), `"VetxOnly": true`) {
		t.Fatalf("stock own-only vet did not establish actual dependency facts-only work: %v\n%s", err, first)
	}
	second, cached := runCapturedCommandOutput(ctx, mainDir, env, "go", "vet", "-x", "-asmdecl", "example.invalid/direct-dep")
	t.Logf("actual %s same-cache explicit dependency error=%v\n%s", runtime.Version(), cached, second)
	if cached != nil && !strings.Contains(discoveryCommandDiagnostic(cached), "invalid offset ret+8(FP)") {
		t.Fatalf("cached baseline failed for an unrelated cause: %v", cached)
	}
	for repeat := 0; repeat < 2; repeat++ {
		err := runDiscoveryAsmDeclDirect(ctx, mainDir, env, nil, []string{"example.invalid/direct-dep"}, "")
		if err == nil || !strings.Contains(discoveryCommandDiagnostic(err), "invalid offset ret+8(FP)") {
			t.Fatalf("direct actual analysis %d reused facts-only success: %v", repeat, err)
		}
		if _, ok := err.(*discoveryCapturedCommandError); !ok {
			t.Fatalf("single actual Exit1 was unnecessarily wrapped: %T", err)
		}
		t.Logf("direct actual analysis %d retained the source ABI diagnostic: %v", repeat, err)
	}
}

func discoveryAsmDeclDirectFixtureEnv(t *testing.T, root string) []string {
	t.Helper()
	return replaceEnv(os.Environ(), map[string]string{
		"PATH":   filepath.Join(runtime.GOROOT(), "bin") + string(os.PathListSeparator) + os.Getenv("PATH"),
		"GOROOT": runtime.GOROOT(), "GOTOOLCHAIN": "local", "GOWORK": "off",
		"GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "0", "GOFLAGS": "-p=2",
		"GOPROXY": "off", "GOSUMDB": "off", "GOPATH": filepath.Join(root, "gopath"),
		"GOMODCACHE": filepath.Join(root, "modules"),
		"GOENV":      "off",
	})
}

func TestDiscoveryAsmDeclDirectActualTestVariantsAndExports(t *testing.T) {
	root, dir, env := discoveryAsmDeclDirectVariantFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	plan, err := captureDiscoveryAsmDeclDirect(ctx, root, env, nil, []string{"./p"}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := plan.close(); err != nil {
			t.Error(err)
		}
	}()
	if len(plan.Units) != 2 {
		t.Fatalf("ordinary/test-only/external-test units were dropped: %#v", plan.Units)
	}
	var original, ptest directAsmDeclPackage
	for _, pkg := range plan.Packages {
		if pkg.ImportPath == "example.invalid/direct-variants/p" {
			original = pkg
		}
		if pkg.ImportPath == "example.invalid/direct-variants/p [example.invalid/direct-variants/p.test]" {
			ptest = pkg
		}
	}
	if original.Export == "" || ptest.Export == "" || original.Export == ptest.Export {
		t.Fatalf("actual distinct original/test exports missing: %q / %q", original.Export, ptest.Export)
	}
	for _, unit := range plan.Units {
		if unit.Config.VetxOnly || unit.Config.SucceedOnTypecheckFailure {
			t.Fatal("official diagnostic execution was disabled")
		}
		if strings.HasPrefix(unit.PackageID, "example.invalid/direct-variants/p_test ") {
			if unit.Config.ImportMap["example.invalid/direct-variants/p"] != "example.invalid/direct-variants/p" || unit.Config.PackageFile["example.invalid/direct-variants/p"] != ptest.Export {
				t.Fatalf("external-test actual variant import/export was substituted: %#v", unit.Config)
			}
		}
	}
	if err := plan.run(ctx); err != nil {
		t.Fatalf("actual valid ordinary + test-only + pxtest failed: %v", err)
	}
	if err := plan.close(); err != nil {
		t.Fatal(err)
	}
	assembly := filepath.Join(dir, "decl_amd64.s")
	data, err := os.ReadFile(assembly)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), "TEXT ·testScope(SB),4,$0-12\nMOVL x+0(FP), AX", "TEXT ·testScope(SB),4,$0-12\nMOVQ x+0(FP), AX", 1))
	writeTestFile(t, assembly, string(data))
	err = runDiscoveryAsmDeclDirect(ctx, root, env, nil, []string{"./p"}, "")
	if err == nil || !strings.Contains(discoveryCommandDiagnostic(err), "testScope: invalid MOVQ") || strings.Contains(discoveryCommandDiagnostic(err), "missing Go declaration") {
		t.Fatalf("test-only declaration/type was lost: %v", err)
	}
	var failure *discoveryCapturedCommandError
	if !errors.As(err, &failure) || failure.directory != root {
		t.Fatalf("direct vet did not retain original request CWD: %v", err)
	}
}

func discoveryAsmDeclDirectVariantFixture(t *testing.T) (string, string, []string) {
	t.Helper()
	root := discoveryAsmDeclRetryPhysicalTemp(t)
	dir := filepath.Join(root, "p")
	for _, subdir := range []string{dir, filepath.Join(root, "dep")} {
		if err := os.MkdirAll(subdir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.invalid/direct-variants\n\ngo 1.20\n")
	writeTestFile(t, filepath.Join(root, "dep", "dep.go"), "package dep\ntype Word uint32\n")
	writeTestFile(t, filepath.Join(dir, "p.go"), "package p\nimport \"example.invalid/direct-variants/dep\"\nfunc Ordinary(x dep.Word) dep.Word\n")
	writeTestFile(t, filepath.Join(dir, "p_test.go"), "package p\nimport \"example.invalid/direct-variants/dep\"\nfunc testScope(x dep.Word) dep.Word\n")
	writeTestFile(t, filepath.Join(dir, "external_test.go"), "package p_test\nimport \"example.invalid/direct-variants/p\"\nvar Call = p.Ordinary\n")
	writeTestFile(t, filepath.Join(dir, "decl_amd64.s"), "TEXT ·Ordinary(SB),4,$0-12\nMOVL x+0(FP), AX\nMOVL AX, ret+8(FP)\nRET\nTEXT ·testScope(SB),4,$0-12\nMOVL x+0(FP), AX\nMOVL AX, ret+8(FP)\nRET\n")
	return root, dir, discoveryAsmDeclDirectFixtureEnv(t, root)
}

func TestDiscoveryAsmDeclDirectPlanMutationsFailClosed(t *testing.T) {
	root, dir, env := discoveryAsmDeclDirectVariantFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	plan, err := captureDiscoveryAsmDeclDirect(ctx, root, env, nil, []string{"./p"}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := plan.close(); err != nil {
			t.Error(err)
		}
	}()
	for name, mutate := range map[string]func(*directAsmDeclPlan){
		"facts-only":        func(p *directAsmDeclPlan) { p.Units[0].Config.VetxOnly = true },
		"typecheck-success": func(p *directAsmDeclPlan) { p.Units[0].Config.SucceedOnTypecheckFailure = true },
		"missing-test-unit": func(p *directAsmDeclPlan) { p.Units = p.Units[:1] },
		"missing-assembly":  func(p *directAsmDeclPlan) { p.Units[0].Config.NonGoFiles = nil },
		"source":            func(p *directAsmDeclPlan) { p.Units[0].Config.GoFiles = nil },
		"tool":              func(p *directAsmDeclPlan) { p.GoBinary = filepath.Join(root, "foreign-go") },
		"sdk":               func(p *directAsmDeclPlan) { p.Minor = 28 },
		"cwd":               func(p *directAsmDeclPlan) { p.Dir = dir },
		"env":               func(p *directAsmDeclPlan) { p.Env = append(p.Env, "GOARCH=386") },
		"export": func(p *directAsmDeclPlan) {
			p.Units[0].Config.PackageFile["foreign"] = filepath.Join(root, "foreign.a")
		},
		"variant-import": func(p *directAsmDeclPlan) {
			p.Units[1].Config.ImportMap["example.invalid/direct-variants/p"] = "foreign"
		},
	} {
		t.Run(name, func(t *testing.T) {
			data, err := json.Marshal(plan)
			if err != nil {
				t.Fatal(err)
			}
			var changed directAsmDeclPlan
			if err := json.Unmarshal(data, &changed); err != nil {
				t.Fatal(err)
			}
			changed.fileIndex = plan.fileIndex
			mutate(&changed)
			if err := changed.verifyBytes(); err == nil {
				t.Fatal("mutated official selection/config identity was accepted")
			}
		})
	}
	for _, path := range []string{filepath.Join(dir, "p.go"), filepath.Join(dir, "decl_amd64.s"), plan.Units[0].Filename} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, append(append([]byte(nil), original...), '\n'), 0600); err != nil {
				t.Fatal(err)
			}
			if err := plan.verifyBytes(); err == nil {
				t.Fatal("actual source/config mutation was accepted")
			}
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
		})
	}
	added := filepath.Join(dir, "late.go")
	writeTestFile(t, added, "package p\n")
	if err := plan.verifyBytes(); err == nil {
		t.Fatal("late selected source was accepted")
	}
	if err := os.Remove(added); err != nil {
		t.Fatal(err)
	}
	if err := plan.verify(ctx); err != nil {
		t.Fatalf("restored original plan no longer verifies: %v", err)
	}
}

func TestDiscoveryAsmDeclDirectSDKAndInputBoundaries(t *testing.T) {
	for _, version := range []string{"go1.19.13", "go1.28.0", "go1.27rc1", "devel go1.27"} {
		if _, err := directAsmDeclSDKMinor(version); err == nil {
			t.Fatalf("unregistered SDK %q accepted", version)
		}
	}
	for _, version := range []string{"go1.20.14", "go1.21.13", "go1.22.12", "go1.27.1"} {
		if _, err := directAsmDeclSDKMinor(version); err != nil {
			t.Fatal(err)
		}
	}
	for _, names := range [][]string{{"../escape.go"}, {"x.go", "x.go"}, {""}, {"a/../x.go"}} {
		if _, err := directAsmDeclAbsFiles(t.TempDir(), names); err == nil {
			t.Fatalf("invalid files accepted: %v", names)
		}
	}
	for _, pkg := range []directAsmDeclPackage{
		{ImportPath: "p [q.test]", ForTest: "p"}, {ImportPath: "p [p.test]"}, {ImportPath: "p [p.test] [p.test]", ForTest: "p"},
	} {
		if _, err := directAsmDeclCanonical(pkg); err == nil {
			t.Fatalf("foreign variant accepted: %#v", pkg)
		}
	}
	for _, env := range [][]string{{}, {"PATH=relative"}, {"PATH=/bin", "PATH=/usr/bin"}, {"BROKEN"}} {
		if _, err := directAsmDeclGoBinary(env); err == nil {
			t.Fatalf("invalid env accepted: %v", env)
		}
	}
}

func TestDiscoveryAsmDeclDirectAlternateModAndAbsentSums(t *testing.T) {
	root, _, env := discoveryAsmDeclDirectVariantFixture(t)
	alternate := filepath.Join(root, "alternate.mod")
	original, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, alternate, string(original))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	plan, err := captureDiscoveryAsmDeclDirect(ctx, root, env, nil, []string{"./p"}, "alternate.mod")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := plan.close(); err != nil {
			t.Error(err)
		}
	}()
	for _, path := range []string{alternate, filepath.Join(root, "go.mod"), filepath.Join(root, "go.sum"), filepath.Join(root, "alternate.sum")} {
		if _, found := plan.fileIndex[path]; !found {
			t.Fatalf("original/effective metadata or absence was not bound: %s", path)
		}
	}
	if err := plan.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"go.sum", "alternate.sum"} {
		path := filepath.Join(root, name)
		writeTestFile(t, path, "late metadata\n")
		if err := plan.verifyBytes(); err == nil {
			t.Fatalf("late %s was accepted", name)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDiscoveryAsmDeclDirectOfficialTypecheckFailureIsNotSuccess(t *testing.T) {
	root, dir, env := discoveryAsmDeclDirectVariantFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	plan, err := captureDiscoveryAsmDeclDirect(ctx, root, env, nil, []string{"./p"}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := plan.close(); err != nil {
			t.Error(err)
		}
	}()
	path := filepath.Join(dir, "p.go")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, path, string(original)+"var invalid int = \"not an int\"\n")
	_, err = runCapturedCommandOutput(ctx, root, env, plan.GoBinary, "tool", "vet", "-asmdecl", plan.Units[0].Filename)
	if err == nil || !strings.Contains(discoveryCommandDiagnostic(err), "cannot use") {
		t.Fatalf("official false SucceedOnTypecheckFailure lost real typecheck error: %v", err)
	}
	if err := plan.run(ctx); err == nil {
		t.Fatal("producer accepted changed source before analysis")
	}
	writeTestFile(t, path, string(original))
}

func TestDiscoveryAsmDeclDirectDirectoryReplacementAndOwnedCleanup(t *testing.T) {
	root, dir, env := discoveryAsmDeclDirectVariantFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	plan, err := captureDiscoveryAsmDeclDirect(ctx, root, env, nil, []string{"./p"}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := plan.close(); err != nil {
			t.Error(err)
		}
	}()
	saved := dir + "-saved"
	if err := os.Rename(dir, saved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := plan.verifyBytes(); err == nil {
		t.Fatal("replaced selected package directory was accepted")
	}
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(saved, dir); err != nil {
		t.Fatal(err)
	}

	// This is a real copy of an actual selected export; never mutate a
	// borrowed SDK or the compiler cache's export file.
	export := ""
	for _, pkg := range plan.Packages {
		if pkg.ImportPath == "example.invalid/direct-variants/dep" {
			export = pkg.Export
		}
	}
	if export == "" {
		t.Fatal("actual dependency export absent")
	}
	vetName := "vet"
	if runtime.GOOS == "windows" {
		vetName += ".exe"
	}
	for name, source := range map[string]string{"export": export, "vet-tool": filepath.Join(plan.SDK["GOTOOLDIR"], vetName), "config-source": filepath.Join(runtime.GOROOT(), "src/cmd/vendor/golang.org/x/tools/go/analysis/unitchecker/unitchecker.go")} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(source)
			if err != nil {
				t.Fatal(err)
			}
			copyPath := filepath.Join(t.TempDir(), "guarded-input")
			writeTestFile(t, copyPath, string(data))
			sha, size, err := directAsmDeclFileSHA(copyPath)
			if err != nil {
				t.Fatal(err)
			}
			input := directAsmDeclSnapshot{Path: copyPath, SHA: sha, Size: size}
			if err := directAsmDeclVerifyFile(input); err != nil {
				t.Fatal(err)
			}
			data[0] ^= 1
			if err := os.WriteFile(copyPath, data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := directAsmDeclVerifyFile(input); err == nil {
				t.Fatal("actual input byte mutation accepted")
			}
		})
	}
	owned := plan.WorkDir
	held := owned + "-held"
	if err := os.Rename(owned, held); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(owned, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(owned, "not-owned")
	writeTestFile(t, marker, "keep\n")
	if err := plan.close(); err == nil {
		t.Fatal("replacement config directory was recursively removed")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("replacement contents were removed: %v", err)
	}
	// Both exact paths are this test's temporary fixtures, not the SDK,
	// shared cache or an unvalidated broad cleanup target.
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(owned); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(held); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoveryAsmDeclDirectStderrAndExpiredCommand(t *testing.T) {
	valid := "go: downloading example.invalid/dep v1.2.3\n"
	if err := directAsmDeclValidateSuccessfulStderr([]string{"list"}, valid); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"unexpected warning\n", valid + "unknown failure\n", "go: downloading INTERNAL_ERROR vBROKEN\n", "go: downloading golang.org/toolchain v0.0.1-go1.27.1.linux-amd64\n", "go: downloading  example.invalid/dep v1.2.3\n"} {
		if err := directAsmDeclValidateSuccessfulStderr([]string{"list"}, text); err == nil {
			t.Fatalf("unknown successful stderr accepted: %q", text)
		}
	}
	if err := directAsmDeclValidateSuccessfulStderr([]string{"env"}, valid); err == nil {
		t.Fatal("env borrowed list-stage download permission")
	}
	root := discoveryAsmDeclRetryPhysicalTemp(t)
	env := discoveryAsmDeclDirectFixtureEnv(t, root)
	binary, err := directAsmDeclGoBinary(env)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := directAsmDeclCommandJSON(ctx, root, env, binary, "env", "-json", "GOROOT"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expired actual command was launched/accepted: %v", err)
	}
}

func TestDiscoveryAsmDeclDirectActualMainWithoutTests(t *testing.T) {
	root := discoveryAsmDeclRetryPhysicalTemp(t)
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.invalid/direct-no-tests\n\ngo 1.20\n")
	writeTestFile(t, filepath.Join(root, "main.go"), "package main\nfunc Input() uint64\nfunc main() {}\n")
	writeTestFile(t, filepath.Join(root, "decl_amd64.s"), "TEXT ·Input(SB),4,$0-8\nMOVQ $3, ret+0(FP)\nRET\n")
	env := discoveryAsmDeclDirectFixtureEnv(t, root)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	plan, err := captureDiscoveryAsmDeclDirect(ctx, root, env, nil, []string{"."}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := plan.close(); err != nil {
			t.Error(err)
		}
	}()
	if len(plan.Units) != 1 || plan.Units[0].PackageID != "example.invalid/direct-no-tests" {
		t.Fatalf("actual main/no-tests units changed: %#v", plan.Units)
	}
	if err := plan.run(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoveryAsmDeclDirectActualConfigRegistrationTypes(t *testing.T) {
	path := filepath.Join(runtime.GOROOT(), "src/cmd/vendor/golang.org/x/tools/go/analysis/unitchecker/unitchecker.go")
	minor, err := directAsmDeclSDKMinor(runtime.Version())
	if err != nil {
		t.Fatal(err)
	}
	if err := directAsmDeclValidateConfigRegistration(path, minor); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pattern := regexp.MustCompile(`(?m)^(\s*VetxOnly\s+)bool`)
	changed := pattern.ReplaceAllString(string(data), `${1}string`)
	if changed == string(data) {
		t.Fatal("actual Config field mutation did not apply")
	}
	copyPath := filepath.Join(t.TempDir(), "unitchecker.go")
	writeTestFile(t, copyPath, changed)
	if err := directAsmDeclValidateConfigRegistration(copyPath, minor); err == nil {
		t.Fatal("same field names with changed official safety type accepted")
	}
}

func TestDiscoveryAsmDeclDirectJSONDeadlineOwnsProcess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	env := replaceEnv(os.Environ(), map[string]string{"PLAN9ASM_EXACT_CLI_HELPER": "wait-for-deadline"})
	// Reuse the existing finite first-party helper, not a fake Go executable
	// or a library program. This tests only the split-output lifecycle.
	_, err := directAsmDeclCommandJSON(ctx, t.TempDir(), env, os.Args[0], "-test.run=^TestDiscoveryExactCandidateCLIHelper$")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("actual split-output process deadline was lost: %v", err)
	}
}

func TestDiscoveryAsmDeclDirectActualListFailureKeepsBothStreams(t *testing.T) {
	root := discoveryAsmDeclRetryPhysicalTemp(t)
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.invalid/direct-old-test\n\ngo 1.20\n")
	writeTestFile(t, filepath.Join(root, "decl.go"), "package p\nfunc Kernel() uint64\n")
	writeTestFile(t, filepath.Join(root, "decl_amd64.s"), "TEXT ·Kernel(SB),4,$0-8\nMOVQ $3, ret+0(FP)\nRET\n")
	writeTestFile(t, filepath.Join(root, "obsolete_test.go"), "package p\nvar oldTest = missingObsoleteDeclaration\n")
	env := discoveryAsmDeclDirectFixtureEnv(t, root)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	err := runDiscoveryAsmDeclDirect(ctx, root, env, nil, []string{"."}, "")
	failure, ok := err.(*discoveryCapturedCommandError)
	if !ok || failure == nil || !strings.Contains(failure.output, "missingObsoleteDeclaration") || failure.directory != root {
		t.Fatalf("actual list source/test error was lost or wrapped: %T %v", err, err)
	}
	t.Logf("actual SDK list failure retains all output without analyzer authority: %v", err)
	if isDiscoveryInfrastructureFailure(err) {
		t.Fatalf("actual compiler output was misclassified as empty infrastructure: %v", err)
	}
}

func TestDiscoveryAsmDeclDirectActualLogicalCacheAlias(t *testing.T) {
	root, _, env := discoveryAsmDeclDirectVariantFixture(t)
	physical := filepath.Join(root, "cache-target")
	logical := filepath.Join(root, "logical-cache")
	if err := os.Mkdir(physical, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(physical, logical); err != nil {
		t.Fatal(err)
	}
	env = replaceEnv(env, map[string]string{"GOCACHE": logical})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	plan, err := captureDiscoveryAsmDeclDirect(ctx, root, env, nil, []string{"./p"}, "")
	if err != nil {
		t.Fatalf("actual stock Go logical cache export alias was rejected: %v", err)
	}
	defer func() {
		if err := plan.close(); err != nil {
			t.Error(err)
		}
	}()
	observed := false
	for _, pkg := range plan.Packages {
		if strings.HasPrefix(pkg.Export, logical+string(filepath.Separator)) {
			observed = true
		}
	}
	if !observed || plan.SDK["GOCACHE"] != logical {
		t.Fatal("actual Go did not retain the requested logical spelling")
	}
	if err := plan.run(ctx); err != nil {
		t.Fatal(err)
	}
	aliases := plan.directoryAliases
	plan.directoryAliases = nil
	if err := plan.verifyBytes(); err == nil {
		t.Fatal("deleting the private directory alias seal was accepted")
	}
	plan.directoryAliases = aliases
	leaf := filepath.Join(root, "leaf-link")
	if err := os.Symlink(filepath.Join(root, "go.mod"), leaf); err != nil {
		t.Fatal(err)
	}
	if err := plan.bindFile(leaf); err == nil {
		t.Fatal("logical parent allowance authorized a leaf file symlink")
	}
	other := filepath.Join(root, "other-cache")
	if err := os.Mkdir(other, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(logical); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, logical); err != nil {
		t.Fatal(err)
	}
	if err := plan.verifyDirectoryIdentities(); err == nil {
		t.Fatal("actual captured logical cache alias was allowed to retarget")
	}
}
