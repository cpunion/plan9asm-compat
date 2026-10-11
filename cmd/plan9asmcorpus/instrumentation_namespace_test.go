package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestInstrumentationNamespaceActualGoVersionReplacement(t *testing.T) {
	// This first-party file proxy tests stock Go's exact version replacement,
	// not external download authentication. No third-party source is executed.
	candidate := discoveryCandidate{Module: "example.invalid/archive", Version: "v1.0.0", AsmFiles: []string{"pkg/probe.s"}}
	canonical := "example.invalid/canonical"
	metadata := "module " + canonical + "\n\ngo 1.20\n"
	files := map[string]string{
		"go.mod": metadata, "pkg/probe.go": "package probe\nfunc Probe()\n",
		"pkg/probe.s": "TEXT ·Probe(SB),4,$0-0\nRET\n",
	}
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	t.Cleanup(func() { _ = writer.Close() })
	for name, body := range files {
		entry, err := writer.Create(candidate.exactKey() + "/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	proxy := t.TempDir()
	versionDir := filepath.Join(proxy, candidate.Module, "@v")
	if err := os.MkdirAll(versionDir, 0700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"v1.0.0.mod": []byte(metadata), "v1.0.0.zip": archive.Bytes(),
		"v1.0.0.info": []byte(`{"Version":"v1.0.0","Time":"2026-10-01T00:00:00Z"}`),
	} {
		if err := os.WriteFile(filepath.Join(versionDir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	cache := t.TempDir()
	t.Cleanup(func() {
		if err := filepath.Walk(cache, func(file string, info os.FileInfo, err error) error {
			if err == nil && info.IsDir() {
				return os.Chmod(file, 0700)
			}
			return err
		}); err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	setup := t.TempDir()
	if err := os.WriteFile(filepath.Join(setup, "go.mod"), []byte("module example.invalid/observer\n\ngo 1.20\n"), 0600); err != nil {
		t.Fatal(err)
	}
	setupEnv := replaceEnv(os.Environ(), map[string]string{
		"GOPROXY": "file://" + proxy, "GOSUMDB": "off", "GOPRIVATE": "", "GONOPROXY": "", "GONOSUMDB": "", "GOMODCACHE": cache,
	})
	stdout, stderr, err := gotoolprofile.RunBounded(ctx, setup, setupEnv, "go", "mod", "download", "-json", candidate.exactKey())
	if err != nil || len(stderr) != 0 {
		t.Fatalf("first-party source transport: %v\n%s", err, stderr)
	}
	var downloaded struct{ Path, Version, Zip, GoMod string }
	if err := json.Unmarshal(stdout, &downloaded); err != nil {
		t.Fatal(err)
	}
	zipBytes, zipErr := os.ReadFile(downloaded.Zip)
	modBytes, modErr := os.ReadFile(downloaded.GoMod)
	if downloaded.Path != candidate.Module || downloaded.Version != candidate.Version || zipErr != nil || modErr != nil ||
		!bytes.Equal(zipBytes, archive.Bytes()) || string(modBytes) != metadata {
		t.Fatal("first-party transport changed exact archive or original metadata")
	}
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		t.Run(target, func(t *testing.T) {
			goos, goarch, _ := strings.Cut(target, "/")
			env := replaceEnv(os.Environ(), map[string]string{
				"GOOS": goos, "GOARCH": goarch, "CGO_ENABLED": "0", "GOPROXY": "file://" + proxy,
				"GOSUMDB": "off", "GOPRIVATE": "", "GONOPROXY": "", "GONOSUMDB": "", "GOMODCACHE": cache,
			})
			for _, declared := range []string{candidate.Module, canonical} {
				plan, err := makeDiscoveryExecutionPlan(candidate, declared)
				if err != nil {
					t.Fatal(err)
				}
				// The observer fixture uses the language common to both SDKs.
				// Production external compilation remains Go 1.27 only.
				goMod := strings.Replace(plan.GoMod, "go 1.27\n", "go 1.20\n", 1)
				dir := t.TempDir()
				if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0600); err != nil {
					t.Fatal(err)
				}
				stdout, stderr, err := gotoolprofile.RunBounded(ctx, dir, env, "go", "list", "-mod=mod", "-export", "-json", plan.Patterns[0])
				if declared == candidate.Module {
					var exit *exec.ExitError
					want := candidate.exactKey() + ": parsing go.mod:\n\tmodule declares its path as: " + canonical +
						"\n\t        but was required as: " + candidate.Module + "\n"
					if !errors.As(err, &exit) || exit.ExitCode() != 1 || len(stdout) != 0 || string(stderr) != want {
						t.Fatalf("original archive-only graph did not reject its exact namespace: %v stdout=%s stderr=%s", err, stdout, stderr)
					}
					continue
				}
				if err != nil || len(stderr) != 0 {
					t.Fatalf("exact original version replacement: %v\n%s", err, stderr)
				}
				var actual struct {
					ImportPath, Dir, Export string
					GoFiles, SFiles         []string
					Module                  struct {
						Path, Version, Dir, GoMod string
						Replace                   *struct{ Path, Version, Dir, GoMod string }
					}
				}
				if err := json.Unmarshal(stdout, &actual); err != nil {
					t.Fatal(err)
				}
				if actual.ImportPath != canonical+"/pkg" || actual.Module.Path != canonical || actual.Module.Version != candidate.Version ||
					actual.Module.Replace == nil || actual.Module.Replace.Path != candidate.Module || actual.Module.Replace.Version != candidate.Version ||
					actual.Module.Dir != actual.Module.Replace.Dir || !equalDiscoveryStrings(actual.GoFiles, []string{"probe.go"}) ||
					!equalDiscoveryStrings(actual.SFiles, []string{"probe.s"}) {
					t.Fatal("actual Go lost the canonical role or exact archive replacement")
				}
				for name, body := range files {
					data, err := os.ReadFile(filepath.Join(actual.Module.Replace.Dir, filepath.FromSlash(name)))
					if err != nil || string(data) != body {
						t.Fatalf("actual replacement changed original member %s: %v", name, err)
					}
				}
				if metadataBytes, err := os.ReadFile(actual.Module.Replace.GoMod); err != nil || string(metadataBytes) != metadata {
					t.Fatalf("actual metadata differs from the original ZIP: %v", err)
				}
				if info, err := os.Stat(actual.Export); err != nil || info.Size() == 0 {
					t.Fatalf("actual Go did not produce a nonempty package object: %v", err)
				}
			}
		})
	}
}

func TestInstrumentationNamespacePortablePlanRequiresOriginalMember(t *testing.T) {
	metadata := "module example.invalid/canonical\n\ngo 1.20\n"
	plan := &discoveryOrdinarySelectionPlan{
		Module: "example.invalid/archive", Version: "v1.0.0",
		InstrumentationPlan: &discoveryInstrumentationPlan{ModuleMetadata: metadata},
		Directories: []ordinarySelectionDirectory{{Directory: ".", Entries: []ordinarySelectionEntry{
			{Name: "go.mod", Kind: "file", SHA256: discoveryFeatureBytesSHA256([]byte(metadata))},
		}}},
	}
	if got, err := discoveryInstrumentationModulePath(plan); err != nil || got != "example.invalid/canonical" {
		t.Fatalf("namespace not derived from original bytes: %q %v", got, err)
	}
	for name, change := range map[string]func(*discoveryOrdinarySelectionPlan){
		"changed metadata":            func(p *discoveryOrdinarySelectionPlan) { p.InstrumentationPlan.ModuleMetadata += "// changed\n" },
		"missing member":              func(p *discoveryOrdinarySelectionPlan) { p.Directories = nil },
		"directory instead of member": func(p *discoveryOrdinarySelectionPlan) { p.Directories[0].Entries[0].Kind = "directory" },
		"duplicate member": func(p *discoveryOrdinarySelectionPlan) {
			p.Directories[0].Entries = append(p.Directories[0].Entries, p.Directories[0].Entries[0])
		},
		"same namespace": func(p *discoveryOrdinarySelectionPlan) { p.Module = "example.invalid/canonical" },
		"wrong hash":     func(p *discoveryOrdinarySelectionPlan) { p.Directories[0].Entries[0].SHA256 = strings.Repeat("0", 64) },
		"proxy metadata": func(p *discoveryOrdinarySelectionPlan) { p.ProxyGoMod = &gotoolprofile.ProxyGoModProof{} },
	} {
		t.Run(name, func(t *testing.T) {
			data, err := json.Marshal(plan)
			if err != nil {
				t.Fatal(err)
			}
			var copied discoveryOrdinarySelectionPlan
			if err := json.Unmarshal(data, &copied); err != nil {
				t.Fatal(err)
			}
			change(&copied)
			if _, err := discoveryInstrumentationModulePath(&copied); err == nil {
				t.Fatal("accepted an unbound portable namespace")
			}
		})
	}
}
