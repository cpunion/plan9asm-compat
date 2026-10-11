package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDiscoveryAsmDeclActualForeignPathCannotRejectOwnSource(t *testing.T) {
	root := t.TempDir()
	for _, module := range []string{"main", "dep"} {
		if err := os.MkdirAll(filepath.Join(root, module, "selected"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	physicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	mainDir := filepath.Join(physicalRoot, "main")
	depDir := filepath.Join(physicalRoot, "dep")
	files := map[string]string{
		filepath.Join(mainDir, "go.mod"): `module example.invalid/pathmain

go 1.20

require example.invalid/pathdep v0.0.0
replace example.invalid/pathdep => ../dep
`,
		filepath.Join(mainDir, "selected", "decl.go"): `package selected
import _ "example.invalid/pathdep/selected"
func Value() uint64
`,
		filepath.Join(mainDir, "selected", "decl_amd64.s"): `TEXT ·Value(SB),4,$0-8
MOVQ $1, ret+0(FP)
RET
`,
		filepath.Join(depDir, "go.mod"):              "module example.invalid/pathdep\n\ngo 1.20\n",
		filepath.Join(depDir, "selected", "decl.go"): "package selected\nfunc Bad() uint64\n",
		filepath.Join(depDir, "selected", "decl_amd64.s"): `TEXT ·Bad(SB),4,$0-8
MOVQ $2, ret+8(FP)
RET
`,
	}
	before := make(map[string][sha256.Size]byte, len(files))
	for name, source := range files {
		writeTestFile(t, name, source)
		before[name] = sha256.Sum256([]byte(source))
		t.Logf("first-party source %s SHA256=%x bytes=%d\n%s", name, before[name], len(source), source)
	}
	t.Cleanup(func() {
		for name, want := range before {
			data, err := os.ReadFile(name)
			if err != nil || sha256.Sum256(data) != want {
				t.Errorf("original fixture source changed during actual Go observations: %s: %v", name, err)
			}
		}
	})

	env := discoveryAsmDeclLocalFixtureEnvironment(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	goPath, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	version, err := runCapturedCommandOutput(ctx, mainDir, env, "go", "version")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("actual Go tool path=%s version=%s", goPath, strings.TrimSpace(string(version)))
	toolDir, err := runCapturedCommandOutput(ctx, mainDir, env, "go", "env", "GOTOOLDIR")
	if err != nil {
		t.Fatal(err)
	}
	tools := make(map[string]string)
	for _, name := range []string{goPath,
		filepath.Join(strings.TrimSpace(string(toolDir)), "vet"),
		filepath.Join(strings.TrimSpace(string(toolDir)), "asm"),
		filepath.Join(strings.TrimSpace(string(toolDir)), "compile")} {
		tools[name] = discoveryAsmDeclPathFileSHA(t, name)
		t.Logf("actual stock-Go tool %s SHA256=%s", name, tools[name])
	}
	t.Cleanup(func() {
		for name, want := range tools {
			if got := discoveryAsmDeclPathFileSHA(t, name); got != want {
				t.Errorf("actual Go tool changed during source observations: %s: %s != %s", name, got, want)
			}
		}
	})
	patterns := []string{"./selected", "example.invalid/pathdep/selected"}
	listArgs := append([]string{"list", "-json"}, patterns...)
	listing, err := runCapturedCommandOutput(ctx, mainDir, env, "go", listArgs...)
	if err != nil {
		t.Fatalf("actual same-target Go package selection failed: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(listing))
	selected := make(map[string]bool)
	for {
		var pkg struct {
			ImportPath, Dir string
			GoFiles, SFiles []string
			Module          *struct{ Path, Dir, GoMod string }
		}
		if err := decoder.Decode(&pkg); err != nil {
			if err == io.EOF {
				break
			}
			t.Fatal(err)
		}
		moduleRoot := mainDir
		modulePath := "example.invalid/pathmain"
		if pkg.ImportPath == "example.invalid/pathdep/selected" {
			moduleRoot, modulePath = depDir, "example.invalid/pathdep"
		} else if pkg.ImportPath != "example.invalid/pathmain/selected" {
			t.Fatalf("unexpected actual Go package in selection: %+v", pkg)
		}
		if pkg.Module == nil || pkg.Module.Path != modulePath || pkg.Module.Dir != moduleRoot ||
			pkg.Dir != filepath.Join(moduleRoot, "selected") ||
			!reflect.DeepEqual(pkg.GoFiles, []string{"decl.go"}) ||
			!reflect.DeepEqual(pkg.SFiles, []string{"decl_amd64.s"}) {
			t.Fatalf("actual Go source identity differs from the two original modules: %+v", pkg)
		}
		selected[pkg.ImportPath] = true
		identity, err := json.Marshal(pkg)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("actual go list CWD=%s GOOS=linux GOARCH=amd64 argv=%v selection=%s", mainDir, listArgs, identity)
	}
	if len(selected) != 2 {
		t.Fatalf("actual Go selection did not include both distinct module identities: %v", selected)
	}

	t.Run("independent stock-Go dependency facts cache observation", func(t *testing.T) {
		cache := t.TempDir()
		warmEnv := replaceEnv(env, map[string]string{"GOCACHE": cache})
		firstArgs := []string{"vet", "-x", "-asmdecl", "./selected"}
		first, firstErr := runCapturedCommandOutput(ctx, mainDir, warmEnv, "go", firstArgs...)
		t.Logf("stock sequence first CWD=%s GOCACHE=%s argv=%v error=%v\n%s", mainDir, cache, firstArgs, firstErr, first)
		if firstErr != nil || !strings.Contains(string(first), `"VetxOnly": true`) {
			t.Fatalf("own-only original vet did not establish a real dependency facts-only action: %v", firstErr)
		}

		secondArgs := []string{"vet", "-x", "-asmdecl", "example.invalid/pathdep/selected"}
		second, secondErr := runCapturedCommandOutput(ctx, mainDir, warmEnv, "go", secondArgs...)
		t.Logf("stock sequence warmed explicit dependency CWD=%s GOCACHE=%s argv=%v error=%v\n%s", mainDir, cache, secondArgs, secondErr, second)
		// Record a completed stock-Go observation, not a permission to accept
		// an unchecked package. A future stock-Go cache repair may report this
		// source error; an unexplained failure remains a hard fixture error.
		if secondErr != nil && !strings.Contains(discoveryCommandDiagnostic(secondErr), "invalid offset ret+8(FP)") {
			t.Fatalf("warmed explicit vet failed for an unrelated cause: %v", secondErr)
		}

		freshCache := t.TempDir()
		freshEnv := replaceEnv(env, map[string]string{"GOCACHE": freshCache})
		fresh, freshErr := runCapturedCommandOutput(ctx, mainDir, freshEnv, "go", secondArgs...)
		t.Logf("stock sequence fresh explicit dependency CWD=%s GOCACHE=%s argv=%v error=%v\n%s", mainDir, freshCache, secondArgs, freshErr, fresh)
		var failure *discoveryCapturedCommandError
		if !errors.As(freshErr, &failure) {
			t.Fatalf("fresh explicit stock-Go vet did not establish the original ABI diagnostic: %v", freshErr)
		}
		exit, ok := failure.cause.(*exec.ExitError)
		if !ok || exit.ExitCode() != 1 || !strings.Contains(failure.output, "invalid offset ret+8(FP)") {
			t.Fatalf("fresh explicit stock-Go vet did not preserve actual exit one and its source error: %v", freshErr)
		}
		if secondErr == nil {
			t.Log("OBSERVED: same-source warmed explicit asmdecl returned exit 0 with no ABI diagnostic; fresh explicit asmdecl returned exit 1. This is not an assembly/object pass.")
		}
	})

	ownEnv := replaceEnv(env, map[string]string{"GOCACHE": t.TempDir()})
	if _, err := runCapturedCommandOutput(ctx, mainDir, ownEnv, "go", "vet", "-asmdecl", "./selected"); err != nil {
		t.Fatalf("original own source is not the required legitimate control: %v", err)
	}
	t.Logf("actual own-only go vet -asmdecl ./selected CWD=%s exit=0", mainDir)

	for _, test := range []struct {
		name, cwd string
		patterns  []string
	}{
		{"foreign relative path suffix", mainDir, patterns},
		{"foreign basename from its own physical directory", filepath.Join(depDir, "selected"), []string{"."}},
	} {
		t.Run(test.name, func(t *testing.T) {
			args := append([]string{"vet", "-asmdecl"}, test.patterns...)
			// A dependency facts-only vet action can populate a warm cache.
			// This source witness uses its own fresh cache, rather than borrowing
			// any earlier package's successful analysis or dependency facts.
			cache := t.TempDir()
			actualEnv := replaceEnv(env, map[string]string{"GOCACHE": cache})
			output, err := runCapturedCommandOutput(ctx, test.cwd, actualEnv, "go", args...)
			t.Logf("actual raw stock-Go CWD=%s argv=%v GOCACHE=%s error=%v output=%s", test.cwd, args, cache, err, output)
			var failure *discoveryCapturedCommandError
			if !errors.As(err, &failure) {
				// Keep a real unexpected success observable. A separate private
				// cache and -x distinguish cached analysis from actual tool work;
				// this diagnostic retry never changes the expected failure.
				debugArgs := append([]string{"vet", "-x", "-asmdecl"}, test.patterns...)
				debugEnv := replaceEnv(env, map[string]string{"GOCACHE": t.TempDir()})
				debugOutput, debugErr := runCapturedCommandOutput(ctx, test.cwd, debugEnv, "go", debugArgs...)
				t.Logf("independent fresh-cache stock-Go CWD=%s argv=%v error=%v\n%s", test.cwd, debugArgs, debugErr, debugOutput)
				t.Fatalf("actual foreign original-source vet did not fail: %v", err)
			}
			exit, ok := failure.cause.(*exec.ExitError)
			if !ok || exit.ExitCode() != 1 {
				t.Fatalf("foreign original-source vet did not supply actual exit-one wait status: %v", err)
			}
			var diagnostic string
			for _, line := range strings.Split(failure.output, "\n") {
				if strings.Contains(line, "invalid offset ret+8(FP); expected ret+0(FP)") {
					if diagnostic != "" {
						t.Fatalf("foreign fixture produced ambiguous ABI diagnostics: %s", failure.output)
					}
					diagnostic = line
				}
			}
			position := discoveryAsmDeclPosition(diagnostic)
			if position == nil {
				t.Fatalf("stock-Go diagnostic lacks a concrete assembly source position: %s", failure.output)
			}
			reported := filepath.FromSlash(position[1])
			if !filepath.IsAbs(reported) {
				reported = filepath.Join(test.cwd, reported)
			}
			physicalReported, err := filepath.EvalSymlinks(reported)
			if err != nil || physicalReported != filepath.Join(depDir, "selected", "decl_amd64.s") {
				t.Fatalf("actual diagnostic does not refer to the foreign physical source: %s: %v", reported, err)
			}
			t.Logf("actual stock-Go CWD=%s argv=%v exit=%d reported=%s physical=%s\n%s", test.cwd, args, exit.ExitCode(), position[1], physicalReported, failure.output)

			// This tests the classification seam, not a claim that the whole
			// production candidate was run or incorrectly marked successful.
			own := []string{"selected/decl_amd64.s"}
			rejected, classifyErr := classifyDiscoveryAsmDeclFailure(mainDir, own, own, failure)
			if classifyErr == nil || len(rejected) != 0 {
				t.Fatalf("actual foreign source was attributed to the valid own candidate: rejected=%v err=%v; CWD=%s physical=%s diagnostic=%s", rejected, classifyErr, test.cwd, physicalReported, diagnostic)
			}
		})
	}
}

func discoveryAsmDeclPathFileSHA(t *testing.T, name string) string {
	t.Helper()
	file, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		t.Fatalf("actual tool is not a readable regular file: %s: %v", name, err)
	}
	hash := sha256.New()
	_, readErr := io.Copy(hash, file)
	closeErr := file.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", hash.Sum(nil))
}
