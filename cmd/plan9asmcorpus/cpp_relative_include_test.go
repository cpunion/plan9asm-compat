package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func fixtureCPPRelativeInclude(t *testing.T, target, include string) (*discoveryOrdinarySelectionPlan, string, string, string) {
	t.Helper()
	arch := strings.Split(target, "/")[1]
	file := "pkg/a/b/native_" + arch + ".s"
	_, root, archive := fixtureCPPInputsForTarget(t, target, map[string]string{
		file:              "#include \"" + include + "\"\nTEXT ·Probe(SB),$0-0\nRET\nDATA ·value(SB)/4,$VALUE\nGLOBL ·value(SB),8,$4\n",
		"pkg/a/b/decl.go": "package fixture\nfunc Probe()\n",
		"field/asm.h":     "#define VALUE 42\n",
	})
	candidate := discoveryCandidate{Module: "example.invalid/cpp-inputs", Version: "v1.0.0", AsmFiles: []string{file}}
	plan, err := captureOrdinarySelectionInputs(candidate, root, []string{target})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyOrdinarySelectionZIP(plan, archive, candidate.Module, candidate.Version, ""); err != nil {
		t.Fatal(err)
	}
	return plan, root, archive, file
}

func TestCPPInputsSelectedModuleRelativeIncludeFiveArchitectureObjects(t *testing.T) {
	tools := make(map[string]string)
	for _, name := range []string{"llc", "opt"} {
		binary, err := exec.LookPath(name)
		if err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(binary, "--version").CombinedOutput()
		if err != nil || !strings.Contains(string(out), "version 22.") {
			t.Fatalf("required LLVM 22 %s: %v\n%s", name, err, out)
		}
		tools[name] = binary
	}
	for _, tc := range []struct {
		target, triple string
		arch           plan9asm.Arch
	}{
		{"linux/386", "i386-unknown-linux-gnu", plan9asm.ArchAMD64},
		{"linux/amd64", "x86_64-unknown-linux-gnu", plan9asm.ArchAMD64},
		{"linux/arm", "armv7-unknown-linux-gnueabihf", plan9asm.ArchARM},
		{"linux/arm64", "aarch64-unknown-linux-gnu", plan9asm.ArchARM64},
		{"js/wasm", "wasm32-unknown-unknown", plan9asm.ArchWASM},
	} {
		t.Run(tc.target, func(t *testing.T) {
			plan, root, archive, file := fixtureCPPRelativeInclude(t, tc.target, "../../../field/asm.h")
			parts := strings.Split(tc.target, "/")
			dir := filepath.Join(root, filepath.FromSlash(filepath.Dir(file)))
			object := filepath.Join(t.TempDir(), "go.o")
			command := exec.Command("go", "tool", "asm", "-S", "-p", "cpprelative", "-I", dir, "-o", object, filepath.Join(root, filepath.FromSlash(file)))
			command.Dir = dir
			command.Env = append(os.Environ(), "GOOS="+parts[0], "GOARCH="+parts[1])
			out, err := command.CombinedOutput()
			if err != nil || !strings.Contains(string(out), "2a 00 00 00") {
				t.Fatalf("actual Go original relative include/data object: %v\n%s", err, out)
			}
			for _, deferred := range []bool{false, true} {
				inputs, err := captureDiscoveryCPPInputsMode(plan, root, runtime.GOROOT(), []string{file}, deferred)
				if err != nil {
					t.Errorf("selected module include rejected (deferred=%t): %v", deferred, err)
					continue
				}
				if inputs.Units[0].Includes["module/"+file+"#0"] != "module/field/asm.h" || len(inputs.Sources) != 2 {
					t.Fatalf("wrong original module binding: %#v", inputs)
				}
				if err := verifyDiscoveryCPPModuleZIP(inputs, plan, archive); err != nil {
					t.Fatal(err)
				}
				if err := verifyDiscoveryCPPInputsUnchanged(inputs, root, runtime.GOROOT()); err != nil {
					t.Fatal(err)
				}
				data, err := json.Marshal(inputs)
				if err != nil {
					t.Fatal(err)
				}
				var replay discoveryCPPInputs
				if err := json.Unmarshal(data, &replay); err != nil {
					t.Fatal(err)
				}
				if err := validateDiscoveryCPPInputs(&replay, plan, []string{file}); err != nil {
					t.Fatal(err)
				}
				if deferred {
					consumed, err := discoveryDeferredCPPConsumption(&replay, replay.Units[0], nil, nil)
					if err != nil || len(consumed) != 2 {
						t.Fatalf("actual bound graph replay: %v %v", consumed, err)
					}
				}
			}
			if t.Failed() {
				return
			}
			source, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(file)))
			if err != nil {
				t.Fatal(err)
			}
			expanded, err := plan9asm.PreprocessAssemblySource(string(source), plan9asm.AssemblyPreprocessOptions{
				FileName: file,
				ReadInclude: func(parent, name string) (string, []byte, error) {
					id, err := discoveryCPPResolveInclude(root, runtime.GOROOT(), file, name)
					if err != nil {
						return "", nil, err
					}
					_, relative, err := discoveryCPPSourceIdentity(id)
					if err != nil {
						return "", nil, err
					}
					body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
					return id, body, err
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := plan9asm.Parse(tc.arch, expanded)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := plan9asm.Translate(parsed, plan9asm.Options{
				Goarch: parts[1], TargetTriple: tc.triple,
				ResolveSym: func(name string) string { return strings.ReplaceAll(name, "·", "cpprelative.") },
				Sigs:       map[string]plan9asm.FuncSig{"cpprelative.Probe": {Ret: plan9asm.Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			outputDir := t.TempDir()
			ll, optimized := filepath.Join(outputDir, "relative.ll"), filepath.Join(outputDir, "relative-o2.ll")
			writeTestFile(t, ll, ir)
			if out, err := exec.Command(tools["opt"], "-S", "-passes=default<O2>", ll, "-o", optimized).CombinedOutput(); err != nil {
				t.Fatalf("LLVM 22 O2: %v\n%s", err, out)
			}
			llvmObject := filepath.Join(outputDir, "llvm.o")
			if out, err := exec.Command(tools["llc"], "-mtriple="+tc.triple, "-filetype=obj", optimized, "-o", llvmObject).CombinedOutput(); err != nil {
				t.Fatalf("LLVM 22 object: %v\n%s", err, out)
			}
			info, err := os.Stat(llvmObject)
			if err != nil || info.Size() == 0 {
				t.Fatalf("LLVM 22 object missing/empty: %v", err)
			}
			t.Log("original Go object, legacy/deferred ZIP/replay and LLVM 22 O2 object passed")
		})
	}
}

func TestCPPInputsRelativeIncludeBoundsRemainClosed(t *testing.T) {
	for _, deferred := range []bool{false, true} {
		plan, root, _, file := fixtureCPPRelativeInclude(t, "linux/amd64", "../../../field/asm.h")
		inputs, err := captureDiscoveryCPPInputsMode(plan, root, runtime.GOROOT(), []string{file}, deferred)
		if err != nil {
			t.Fatal(err)
		}
		for _, target := range []string{"tool/../field/asm.h", "tool/pkg/include/textflag.h", "module/other.h"} {
			inputs.Units[0].Includes["module/"+file+"#0"] = target
			if err := validateDiscoveryCPPInputs(inputs, plan, []string{file}); err == nil {
				t.Fatalf("forged relative include accepted: deferred=%t target=%s", deferred, target)
			}
		}
		inputs.Units[0].Includes["module/"+file+"#0"] = "module/field/asm.h"
		inputs.Units[0].DeferredIncludes["module/"+file+"#0"] = "unresolved_include"
		if err := validateDiscoveryCPPInputs(inputs, plan, []string{file}); err == nil {
			t.Fatalf("both bound/deferred origins accepted: deferred=%t", deferred)
		}
		for _, include := range []string{"../../../../outside.h", "../../../missing.h"} {
			plan, root, _, file := fixtureCPPRelativeInclude(t, "linux/amd64", include)
			if _, err := captureDiscoveryCPPInputsMode(plan, root, runtime.GOROOT(), []string{file}, deferred); err == nil {
				t.Fatalf("module/tool escape became registration: deferred=%t include=%s", deferred, include)
			}
		}
	}
}
