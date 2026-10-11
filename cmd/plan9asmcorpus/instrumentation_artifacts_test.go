package main

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestDiscoveryInstrumentationGeneratedArtifactsHaveIndependentBounds(t *testing.T) {
	root := t.TempDir()
	ir := filepath.Join(root, "instrumented-0000.ll")
	file, err := os.OpenFile(ir, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	header := "target triple = \"aarch64-unknown-linux-gnu\"\ndefine void @artifact() { ret void }\n"
	if _, err := io.WriteString(file, header); err != nil {
		t.Fatal(err)
	}
	// Actual valid LLVM text, not a sparse-file size or an original source.
	comment := "; generated artifact filler\n"
	chunk := strings.Repeat(comment, (1<<20)/len(comment))
	for total := len(header); total <= 64<<20; total += len(chunk) {
		if _, err := io.WriteString(file, chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := gotoolprofile.CPPRegularSource(root, filepath.Base(ir)); err == nil {
		t.Fatal("generated output incorrectly enlarged the original CPP source limit")
	}
	llc, err := exec.LookPath("llc")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	version, stderr, err := gotoolprofile.RunBounded(ctx, root, os.Environ(), llc, "--version")
	if err != nil || len(stderr) != 0 || !strings.Contains(string(version), "LLVM version 22.") {
		t.Fatalf("required actual LLVM22 identity: %v; %s; %s", err, version, stderr)
	}
	object := strings.TrimSuffix(ir, ".ll") + ".o"
	stdout, stderr, err := gotoolprofile.RunBounded(ctx, root, os.Environ(), llc, "-O0", "-filetype=obj", ir, "-o", object)
	if err != nil || len(stdout)+len(stderr) != 0 {
		t.Fatalf("actual first-party generated IR/object: %v; %s; %s", err, stdout, stderr)
	}
	irSHA, err := gotoolprofile.FileSHA256(ir)
	if err != nil {
		t.Fatal(err)
	}
	objectSHA, err := gotoolprofile.FileSHA256(object)
	if err != nil {
		t.Fatal(err)
	}
	artifacts, err := gotoolprofile.CaptureInstrumentationLLVMArtifacts(root, 0, &gotoolprofile.InstrumentationLLVMArtifactBudget{})
	if err != nil {
		t.Fatal(err)
	}
	proof := &gotoolprofile.InstrumentationInvocationProof{
		Consumption: &gotoolprofile.InstrumentationConsumptionProof{
			Protocol: gotoolprofile.InstrumentationConsumptionProtocol,
			Files: []gotoolprofile.InstrumentationAssemblyFile{{
				Output:    gotoolprofile.OutputProof{File: "original.s", Part: filepath.Base(ir), IR: irSHA, Object: objectSHA},
				Artifacts: artifacts,
			}},
		},
	}
	info, err := os.Stat(ir)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("actual generated IR bytes=%d SHA256=%s; object SHA256=%s", info.Size(), irSHA, objectSHA)
	if err := verifyDiscoveryInstrumentationPhysicalOutputs(root, proof); err != nil {
		t.Fatalf("compiled generated artifact was rejected by the original-source role: %v", err)
	}
	// This fixture exercises only the physical artifact seam, not the complete
	// source/metadata/type/CPP proof and not a candidate pass.
	if proof.ObjectCount != 0 {
		t.Fatal("unvalidated artifact fixture acquired object-count permission")
	}
}

func TestDiscoveryInstrumentationArtifactPhysicalMutationsStayFailures(t *testing.T) {
	for _, name := range []string{"IR final byte", "object final byte", "delete role pair", "old consumption", "duplicate ordinal", "changed ordinal", "source role", "size", "digest", "symlink", "directory", "missing", "unknown error"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			for _, file := range []string{"instrumented-0000.ll", "instrumented-0000.o"} {
				if err := os.WriteFile(filepath.Join(root, file), []byte("artifact seam, not a compilation certificate\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			artifacts, err := gotoolprofile.CaptureInstrumentationLLVMArtifacts(root, 0, &gotoolprofile.InstrumentationLLVMArtifactBudget{})
			if err != nil {
				t.Fatal(err)
			}
			proof := &gotoolprofile.InstrumentationInvocationProof{Consumption: &gotoolprofile.InstrumentationConsumptionProof{
				Protocol: gotoolprofile.InstrumentationConsumptionProtocol,
				Files: []gotoolprofile.InstrumentationAssemblyFile{{Output: gotoolprofile.OutputProof{
					Part: artifacts.IR.Name, IR: artifacts.IR.SHA256, Object: artifacts.Object.SHA256,
				}, Artifacts: artifacts}},
			}}
			file := &proof.Consumption.Files[0]
			switch name {
			case "IR final byte", "object final byte":
				path := filepath.Join(root, artifacts.IR.Name)
				if name == "object final byte" {
					path = filepath.Join(root, artifacts.Object.Name)
				}
				f, err := os.OpenFile(path, os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, writeErr := f.WriteAt([]byte("x"), artifacts.IR.Bytes-1)
				closeErr := f.Close()
				if writeErr != nil || closeErr != nil {
					t.Fatalf("mutation: %v; %v", writeErr, closeErr)
				}
			case "delete role pair":
				file.Artifacts = nil
			case "old consumption":
				proof.Consumption.Protocol = "actual_go_instrumentation_llvm_objects_v1"
			case "duplicate ordinal":
				proof.Consumption.Files = append(proof.Consumption.Files, *file)
			case "changed ordinal":
				file.Output.Part = "instrumented-0001.ll"
			case "source role":
				file.Artifacts.IR.Role = "module_source"
			case "size":
				file.Artifacts.IR.Bytes++
			case "digest":
				file.Output.IR = strings.Repeat("0", 64)
			case "symlink", "directory", "missing":
				path := filepath.Join(root, artifacts.IR.Name)
				if err := os.Rename(path, path+".retained"); err != nil {
					t.Fatal(err)
				}
				if name == "symlink" {
					if err := os.Symlink(path+".retained", path); err != nil {
						t.Fatal(err)
					}
				} else if name == "directory" {
					if err := os.Mkdir(path, 0700); err != nil {
						t.Fatal(err)
					}
				}
			case "unknown error":
				root = filepath.Join(root, "missing", "unknown")
			}
			if err := verifyDiscoveryInstrumentationPhysicalOutputs(root, proof); err == nil {
				t.Fatal("artifact mutation became physical success")
			}
		})
	}
}

func TestDiscoveryInstrumentationArtifactsLLVM22FiveArchitectures(t *testing.T) {
	llc, err := exec.LookPath("llc")
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"i386-unknown-linux-gnu", "x86_64-unknown-linux-gnu", "armv7-unknown-linux-gnueabihf", "aarch64-unknown-linux-gnu", "wasm32-unknown-unknown"} {
		t.Run(triple, func(t *testing.T) {
			root := t.TempDir()
			ir := filepath.Join(root, "instrumented-0000.ll")
			if err := os.WriteFile(ir, []byte("define i32 @artifact(i32 %input) {\n %answer = add i32 %input, 1\n ret i32 %answer\n}\n"), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			version, stderr, err := gotoolprofile.RunBounded(ctx, root, os.Environ(), llc, "--version")
			if err != nil || len(stderr) != 0 || !strings.Contains(string(version), "LLVM version 22.") {
				t.Fatalf("LLVM22: %v; %s; %s", err, version, stderr)
			}
			stdout, stderr, err := gotoolprofile.RunBounded(ctx, root, os.Environ(), llc, "-O0", "-filetype=obj", "-mtriple="+triple, ir, "-o", filepath.Join(root, "instrumented-0000.o"))
			if err != nil || len(stdout)+len(stderr) != 0 {
				t.Fatalf("actual LLVM22 %s object: %v; %s; %s", triple, err, stdout, stderr)
			}
			artifact, err := gotoolprofile.CaptureInstrumentationLLVMArtifacts(root, 0, &gotoolprofile.InstrumentationLLVMArtifactBudget{})
			if err != nil {
				t.Fatal(err)
			}
			output := gotoolprofile.OutputProof{Part: artifact.IR.Name, IR: artifact.IR.SHA256, Object: artifact.Object.SHA256}
			if err := gotoolprofile.ValidateInstrumentationLLVMArtifacts(0, output, artifact, &gotoolprofile.InstrumentationLLVMArtifactBudget{}); err != nil {
				t.Fatal(err)
			}
			t.Logf("actual object %s bytes=%d SHA256=%s (artifact layer only)", triple, artifact.Object.Bytes, artifact.Object.SHA256)
		})
	}
}
