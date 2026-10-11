package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

func TestDiscoveryAsmDeclRetryMainAndDependencyTopology(t *testing.T) {
	for _, test := range []struct {
		name              string
		secondReplacement bool
		selectDependency  bool
	}{
		{"relative replacement from copied main", false, false},
		{"main and nested dependency selected", false, true},
		{"two version-specific replacements", true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				if failure := recover(); failure != nil {
					t.Fatalf("actual testless retry panicked: %v\n%s", failure, debug.Stack())
				}
			}()

			root := discoveryAsmDeclRetryPhysicalTemp(t)
			main := filepath.Join(root, "main module")
			dependency := filepath.Join(root, "dependency one")
			other := filepath.Join(root, "dependency two")
			for _, dir := range []string{main, dependency, other} {
				if err := os.MkdirAll(filepath.Join(dir, "sub"), 0755); err != nil {
					t.Fatal(err)
				}
			}
			goMod := "module example.invalid/retry-main\n\ngo 1.20\n\n" +
				"require example.invalid/retry-dep v1.0.0\n" +
				"replace example.invalid/retry-dep v1.0.0 => \"../dependency one\"\n"
			if test.secondReplacement {
				goMod += "replace example.invalid/retry-dep v1.1.0 => \"../dependency two\"\n"
			}
			writeTestFile(t, filepath.Join(main, "go.mod"), goMod)
			for _, dir := range []string{dependency, other} {
				writeTestFile(t, filepath.Join(dir, "go.mod"), "module example.invalid/retry-dep\n\ngo 1.20\n")
				discoveryAsmDeclRetryWritePackage(t, filepath.Join(dir, "sub"), "", "missingDependencyTest")
			}
			discoveryAsmDeclRetryWritePackage(t, filepath.Join(main, "sub"),
				"import _ \"example.invalid/retry-dep/sub\"\n", "missingMainTest")
			patterns := []string{"example.invalid/retry-main/sub"}
			if test.selectDependency {
				patterns = append(patterns, "example.invalid/retry-dep/sub")
			}
			env := discoveryAsmDeclRetryEnvironment(t, root)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			listArgs := append([]string{"list", "-json"}, patterns...)
			listed, err := runCapturedCommandOutput(ctx, main, env, "go", listArgs...)
			if err != nil {
				t.Fatalf("original Go package selection failed: %v", err)
			}
			decoder := json.NewDecoder(bytes.NewReader(listed))
			for index, pattern := range patterns {
				var pkg struct {
					ImportPath, Dir string
					TestGoFiles     []string
					Module          struct {
						Path, Version, Dir, GoMod string
						Main                      bool
						Replace                   *struct{ Path, Version, Dir, GoMod string }
					}
				}
				if err := decoder.Decode(&pkg); err != nil {
					t.Fatal(err)
				}
				if pkg.ImportPath != pattern || len(pkg.TestGoFiles) != 1 {
					t.Fatalf("unexpected original package selection: %+v", pkg)
				}
				if index == 0 {
					if !pkg.Module.Main || pkg.Module.Version != "" || pkg.Module.Dir != main {
						t.Fatalf("main-module identity changed: %+v", pkg.Module)
					}
				} else if pkg.Module.Main || pkg.Module.Version != "v1.0.0" || pkg.Module.Dir != dependency ||
					pkg.Module.Replace == nil || pkg.Module.Replace.Dir != dependency {
					t.Fatalf("exact replaced dependency identity changed: %+v", pkg.Module)
				}
				t.Logf("original package identity: %+v", pkg)
			}

			vetArgs := append([]string{"vet", "-asmdecl", "-mod=mod"}, patterns...)
			_, original := runCapturedCommandOutput(ctx, main, env, "go", vetArgs...)
			discoveryAsmDeclRetryRequireActualFailure(t, original, "missingMainTest")
			t.Logf("original completed Go failure: %v", original)
			if err := runDiscoveryAsmDeclWithTestlessModuleCopies(ctx, main, env, vetArgs, nil, patterns); err != nil {
				t.Fatalf("testless copies did not preserve actual main/dependency topology: %v", err)
			}
			unchanged, err := os.ReadFile(filepath.Join(main, "go.mod"))
			if err != nil || string(unchanged) != goMod {
				t.Fatalf("retry changed original main go.mod: %v\n%s", err, unchanged)
			}
		})
	}
}

func TestDiscoveryAsmDeclRetryAlternateSumUsesOriginalInput(t *testing.T) {
	for _, stale := range []bool{false, true} {
		t.Run(fmt.Sprintf("stale_alternate_%t", stale), func(t *testing.T) {
			root := discoveryAsmDeclRetryPhysicalTemp(t)
			work := filepath.Join(root, "work")
			target := filepath.Join(root, "target")
			proxy := filepath.Join(root, "proxy")
			for _, dir := range []string{work, target, proxy} {
				if err := os.MkdirAll(dir, 0755); err != nil {
					t.Fatal(err)
				}
			}
			const leaf = "example.invalid/retry-leaf"
			const version = "v1.0.0"
			discoveryAsmDeclRetryWriteProxy(t, proxy, leaf, version)
			writeTestFile(t, filepath.Join(work, "go.mod"),
				"module example.invalid/retry-driver\n\ngo 1.20\n\n"+
					"require (\nexample.invalid/retry-target v1.0.0\n"+leaf+" "+version+"\n)\n"+
					"replace example.invalid/retry-target => ../target\n")
			writeTestFile(t, filepath.Join(target, "go.mod"),
				"module example.invalid/retry-target\n\ngo 1.20\n\nrequire "+leaf+" "+version+"\n")
			discoveryAsmDeclRetryWritePackage(t, target, "import _ \""+leaf+"\"\n", "missingTargetTest")
			env := replaceEnv(discoveryAsmDeclRetryEnvironment(t, root), map[string]string{
				"GOPROXY": (&url.URL{Scheme: "file", Path: filepath.ToSlash(proxy)}).String(),
			})
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if _, err := runCapturedCommandOutput(ctx, work, env, "go", "mod", "download", leaf+"@"+version); err != nil {
				t.Fatalf("actual owned file-proxy download failed: %v", err)
			}
			originalSum, err := os.ReadFile(filepath.Join(work, "go.sum"))
			if err != nil || !strings.Contains(string(originalSum), leaf+" "+version+"/go.mod h1:") {
				t.Fatalf("actual Go did not record the original checksum input: %v\n%s", err, originalSum)
			}
			if stale {
				// A previous alternate-modfile checksum is not an input of the
				// original successful module selection. It must not override it.
				writeTestFile(t, filepath.Join(work, ".plan9asm-vet.sum"),
					leaf+" "+version+"/go.mod h1:"+strings.Repeat("A", 43)+"=\n")
			}
			patterns := []string{"example.invalid/retry-target"}
			vetArgs := append([]string{"vet", "-asmdecl", "-mod=mod"}, patterns...)
			_, original := runCapturedCommandOutput(ctx, work, env, "go", vetArgs...)
			discoveryAsmDeclRetryRequireActualFailure(t, original, "missingTargetTest")
			t.Logf("original completed Go failure: %v", original)
			if err := runDiscoveryAsmDeclWithTestlessModuleCopies(ctx, work, env, vetArgs, nil, patterns); err != nil {
				t.Fatalf("alternate sum changed the original module/checksum inputs: %v", err)
			}
			alternateSum, err := os.ReadFile(filepath.Join(work, ".plan9asm-vet.sum"))
			if err != nil || !bytes.Equal(alternateSum, originalSum) {
				t.Fatalf("alternate sum differs from actual original selected checksums: %v\noriginal=%s\nalternate=%s", err, originalSum, alternateSum)
			}
			unchanged, err := os.ReadFile(filepath.Join(work, "go.sum"))
			if err != nil || !bytes.Equal(unchanged, originalSum) {
				t.Fatalf("retry changed the original go.sum: %v", err)
			}
		})
	}
}

func TestDiscoveryAsmDeclRetryRelativeReplacementPreservesExactOverride(t *testing.T) {
	for _, test := range []struct {
		name                 string
		wildcardFirst, block bool
	}{
		{"single wildcard first", true, false},
		{"single exact first", false, false},
		{"block wildcard first", true, true},
		{"block exact first", false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				if failure := recover(); failure != nil {
					t.Fatalf("actual relative-replacement retry panicked: %v\n%s", failure, debug.Stack())
				}
			}()
			root := discoveryAsmDeclRetryPhysicalTemp(t)
			main := filepath.Join(root, "main")
			wide := filepath.Join(root, "dependency one")
			narrow := filepath.Join(root, "dependency two")
			for _, dir := range []string{filepath.Join(main, "sub"), wide, narrow} {
				if err := os.MkdirAll(dir, 0755); err != nil {
					t.Fatal(err)
				}
			}
			const dependency = "example.invalid/rebase-dep"
			wildcard := dependency + " => \"../dependency one\"\n"
			exact := dependency + " v1.0.0 => \"../dependency two\"\n"
			if !test.block {
				wildcard = "replace " + wildcard
				exact = "replace " + exact
			}
			replacements := exact + wildcard
			if test.wildcardFirst {
				replacements = wildcard + exact
			}
			if test.block {
				replacements = "replace (\n" + replacements + ")\n"
			}
			goMod := "module example.invalid/rebase-main\n\ngo 1.20\n\nrequire " + dependency + " v1.0.0\n" + replacements
			writeTestFile(t, filepath.Join(main, "go.mod"), goMod)
			for _, dep := range []struct{ dir, underlying string }{{wide, "uint64"}, {narrow, "uint32"}} {
				writeTestFile(t, filepath.Join(dep.dir, "go.mod"), "module "+dependency+"\n\ngo 1.20\n")
				writeTestFile(t, filepath.Join(dep.dir, "decl.go"), "package dependency\ntype Input "+dep.underlying+"\n")
			}
			writeTestFile(t, filepath.Join(main, "sub", "decl.go"),
				"package retry\nimport dependency \""+dependency+"\"\nfunc Value(x dependency.Input)\n")
			writeTestFile(t, filepath.Join(main, "sub", "decl_amd64.s"),
				"TEXT ·Value(SB),$0-8\nMOVQ x+0(FP), AX\nRET\n")
			// The original file never changes between the independent source
			// oracle and retry. This tag controls only the obsolete test, not
			// either declaration, module selection or assembly instruction.
			writeTestFile(t, filepath.Join(main, "sub", "decl_test.go"),
				"//go:build obsolete_test\n// +build obsolete_test\n\npackage retry\nvar obsolete = missingMainTest\n")
			env := discoveryAsmDeclRetryEnvironment(t, root)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			listed, err := runCapturedCommandOutput(ctx, main, env, "go", "list", "-json", dependency)
			if err != nil {
				t.Fatalf("original dependency selection failed: %v", err)
			}
			var selected struct {
				ImportPath, Dir string
				Module          struct {
					Path, Version, Dir, GoMod string
					Main                      bool
					Replace                   *struct{ Path, Version, Dir, GoMod string }
				}
			}
			if err := json.Unmarshal(listed, &selected); err != nil {
				t.Fatal(err)
			}
			if selected.ImportPath != dependency || selected.Dir != narrow || selected.Module.Path != dependency ||
				selected.Module.Version != "v1.0.0" || selected.Module.Main || selected.Module.Replace == nil ||
				selected.Module.Replace.Dir != narrow || selected.Module.Replace.GoMod != filepath.Join(narrow, "go.mod") {
				t.Fatalf("original Go did not select the exact narrow dependency: %+v", selected)
			}
			t.Logf("actual exact dependency: %s@%s Dir=%s GoMod=%s Replace=%+v",
				selected.Module.Path, selected.Module.Version, selected.Dir, selected.Module.GoMod, selected.Module.Replace)
			patterns := []string{"example.invalid/rebase-main/sub"}
			_, sourceABI := runCapturedCommandOutput(ctx, main, env, "go", "vet", "-asmdecl", "-mod=mod", patterns[0])
			discoveryAsmDeclRetryRequireActualFailure(t, sourceABI, "wrong argument size 8; expected $...-4")
			t.Logf("actual unchanged production ABI failure: %v", sourceABI)
			vetArgs := append([]string{"vet", "-asmdecl", "-mod=mod", "-tags=obsolete_test"}, patterns...)
			_, withTest := runCapturedCommandOutput(ctx, main, env, "go", vetArgs...)
			discoveryAsmDeclRetryRequireActualFailure(t, withTest, "missingMainTest")
			t.Logf("actual unchanged selected-test failure: %v", withTest)
			err = runDiscoveryAsmDeclWithTestlessModuleCopies(ctx, main, env, vetArgs, []string{"obsolete_test"}, patterns)
			// The existing ABI0 metadata filter may legitimately remove the
			// tail-padding size warning. It must retain the independent typed
			// eight-byte read from the exact dependency's four-byte argument.
			diagnostic := discoveryCommandDiagnostic(err)
			if err == nil || !strings.Contains(diagnostic, "invalid MOVQ of x+0(FP)") ||
				!strings.Contains(diagnostic, "is 4-byte value") {
				t.Fatalf("retry changed the exact dependency source/type or lost its actual ABI failure: %v", err)
			}
			unchanged, readErr := os.ReadFile(filepath.Join(main, "go.mod"))
			if readErr != nil || string(unchanged) != goMod {
				t.Fatalf("retry changed the original module mapping: %v\n%s", readErr, unchanged)
			}
		})
	}
}

func discoveryAsmDeclRetryPhysicalTemp(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func discoveryAsmDeclRetryEnvironment(t *testing.T, root string) []string {
	t.Helper()
	return replaceEnv(discoveryAsmDeclLocalFixtureEnvironment(t), map[string]string{
		"GOFLAGS": "-mod=mod -modcacherw", "GOSUMDB": "off",
		"GONOPROXY": "none", "GONOSUMDB": "", "GOPRIVATE": "",
		"GOPATH": filepath.Join(root, "gopath"), "GOMODCACHE": filepath.Join(root, "modules"),
	})
}

func discoveryAsmDeclRetryWritePackage(t *testing.T, dir, imports, invalidTest string) {
	t.Helper()
	writeTestFile(t, filepath.Join(dir, "decl.go"), "package retry\n"+imports+"func Value() uint32\n")
	writeTestFile(t, filepath.Join(dir, "decl_amd64.s"), "TEXT ·Value(SB),$0-4\nMOVL $7, ret+0(FP)\nRET\n")
	writeTestFile(t, filepath.Join(dir, "decl_test.go"), "package retry\nvar obsolete = "+invalidTest+"\n")
}

func discoveryAsmDeclRetryRequireActualFailure(t *testing.T, err error, diagnostic string) {
	t.Helper()
	var captured *discoveryCapturedCommandError
	if !errors.As(err, &captured) {
		t.Fatalf("original Go did not produce a completed failure: %v", err)
	}
	exit, ok := captured.cause.(*exec.ExitError)
	if !ok || exit.ExitCode() != 1 || !strings.Contains(captured.output, diagnostic) {
		t.Fatalf("original Go did not produce the exact fixture error with exit 1: %v", err)
	}
}

func discoveryAsmDeclRetryWriteProxy(t *testing.T, proxy, module, version string) {
	t.Helper()
	dir := filepath.Join(proxy, filepath.FromSlash(module), "@v")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	goMod := "module " + module + "\n\ngo 1.20\n"
	writeTestFile(t, filepath.Join(dir, version+".mod"), goMod)
	writeTestFile(t, filepath.Join(dir, version+".info"), `{"Version":"`+version+`","Time":"2026-01-01T00:00:00Z"}`+"\n")
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	for _, file := range []struct{ name, contents string }{
		{"go.mod", goMod}, {"leaf.go", "package leaf\nconst Value = 7\n"},
	} {
		entry, err := writer.Create(module + "@" + version + "/" + file.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(file.contents)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, version+".zip"), archive.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
}
