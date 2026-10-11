//go:build go1.27

package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCPPHeaderPlanningRetainsQueryOnlyOrdinaryOwner(t *testing.T) {
	testCPPHeaderPlanningRetainsQueryOnlyOrdinaryOwner(t, "1.20")
}

func TestCPPHeaderPlanningRetainsCurrentPatchRequirement(t *testing.T) {
	testCPPHeaderPlanningRetainsQueryOnlyOrdinaryOwner(t, strings.TrimPrefix(runtime.Version(), "go"))
}

func testCPPHeaderPlanningRetainsQueryOnlyOrdinaryOwner(t *testing.T, language string) {
	t.Helper()
	compilerEnv := os.Environ()
	candidate := discoveryCandidate{Module: "example.invalid/planning-owner", Version: "v1.0.0", AsmFiles: []string{"probe_amd64.s"}}
	dependency := discoveryCandidate{Module: "example.invalid/planning-assets", Version: "v1.0.0"}
	sources := map[string]string{
		"go.mod":        "module " + candidate.Module + "\ngo " + language + "\nrequire " + dependency.Module + " v1.0.0\n",
		"probe.go":      "package owner\nimport _ \"" + dependency.Module + "\"\nconst Answer=7\nfunc Probe() uint64\n",
		"probe_amd64.s": "#include \"go_asm.h\"\nTEXT ·Probe(SB),4,$0-8\nMOVQ $const_Answer,ret+0(FP)\nRET\n",
	}
	seed := fixtureProfileModuleDownload(t, candidate, sources)
	installGeneratedFixtureProxy(t, candidate, seed, sources["go.mod"])
	cacheRoot := os.Getenv("GOMODCACHE")
	t.Cleanup(func() {
		if err := filepath.Walk(cacheRoot, func(file string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return os.Chmod(file, 0700)
			}
			return nil
		}); err != nil {
			t.Error(err)
		}
	})
	foreign := map[string]string{
		"go.mod":    "module " + dependency.Module + "\ngo 1.20\n",
		"source.go": "package assets\nimport _ \"embed\"\n//go:embed asset.bin\nvar Asset []byte\n",
		"asset.bin": "original foreign planning-only asset\n",
	}
	external := fixtureProfileModuleDownload(t, dependency, foreign)
	versions := filepath.Join(strings.TrimPrefix(os.Getenv("GOPROXY"), "file://"), dependency.Module, "@v")
	if err := os.MkdirAll(versions, 0700); err != nil {
		t.Fatal(err)
	}
	archive, err := os.ReadFile(external.Zip)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"v1.0.0.mod": []byte(foreign["go.mod"]), "v1.0.0.zip": archive,
		"v1.0.0.info": []byte(`{"Version":"v1.0.0","Time":"2026-10-01T00:00:00Z"}`),
	} {
		if err := os.WriteFile(filepath.Join(versions, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	root, err := fixtureTranslatorRoot()
	if err != nil {
		t.Fatal(err)
	}
	translator := filepath.Join(t.TempDir(), "plan9asmll")
	command := exec.CommandContext(ctx, "go", "build", "-p=1", "-o", translator, ".")
	command.Dir, command.Env = filepath.Join(root, "cmd/plan9asmll"), compilerEnv
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build first-party query consumer: %v\n%s", err, output)
	}
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	goBinary, err = filepath.Abs(goBinary)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	load := func(exact string) moduleDownloadInfo {
		data, _, err := runDiscoveryMachineCommand(ctx, dir, os.Environ(), goBinary, "mod", "download", "-json", exact)
		if err != nil {
			t.Fatal(err)
		}
		var result moduleDownloadInfo
		if err := json.Unmarshal(data, &result); err != nil || result.Dir == "" {
			t.Fatalf("actual first-party proxy download: %s; %v", data, err)
		}
		return result
	}
	download := load(candidate.exactKey())
	actualForeign := load(dependency.exactKey())
	plan, err := captureOrdinarySelectionInputs(candidate, download.Dir, []string{"linux/amd64"})
	if err != nil {
		t.Fatal(err)
	}
	plan.ModuleSum = download.Sum
	plan.ZipSHA256, err = discoveryFeatureFileSHA256(download.Zip)
	if err != nil {
		t.Fatal(err)
	}
	if err := installDiscoveryHeaderPlanning(ctx, plan, candidate, download, dir, runtime.GOROOT(), goBinary,
		t.TempDir(), translator, os.Environ(), &discoveryFeatureObservationCache{}); err != nil {
		t.Fatal(err)
	}
	request := discoveryFeatureProfileRequest{Target: "linux/amd64", Baseline: true}
	query := func() error {
		_, err := plan.headerPlanningCapture(request, candidate.AsmFiles[0], nil)
		return err
	}
	if err := query(); err != nil {
		t.Fatalf("actual planning-only header: %v", err)
	}
	if plan.HeaderPlanning == nil || len(plan.HeaderPlanning.Queries) != 1 || len(plan.GeneratedHeaders) != 0 {
		t.Fatal("this fixture must complete planning without any final execution query")
	}
	if err := query(); err != nil || plan.headerPlanningQueryStarts != 1 {
		t.Fatalf("unchanged cached query: %v", err)
	}
	t.Run("mutable projection", func(t *testing.T) {
		for index := range plan.HeaderPlanning.Queries[0].Metadata.Dependencies.SourceModules {
			source := &plan.HeaderPlanning.Queries[0].Metadata.Dependencies.SourceModules[index]
			if source.SourceModule != dependency.Module {
				continue
			}
			before := source.Sources["asset.bin"]
			if before == "" {
				t.Fatal("actual foreign asset is missing from portable proof")
			}
			source.Sources["asset.bin"] = strings.Repeat("f", 64)
			t.Cleanup(func() { source.Sources["asset.bin"] = before })
			if err := verifyDiscoveryOrdinaryDependencySnapshots(plan); err != nil {
				t.Fatalf("mutable report projection changed the private source guard: %v", err)
			}
			if err := query(); err == nil {
				t.Fatal("cached replay accepted a modified portable projection")
			}
			return
		}
		t.Fatal("actual query omitted its foreign dependency")
	})
	t.Run("directory", func(t *testing.T) {
		if err := os.Chmod(actualForeign.Dir, 0700); err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(actualForeign.Dir, "new.bin")
		if err := os.WriteFile(file, []byte("late member"), 0600); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.Remove(file); err != nil {
				t.Error(err)
			}
		})
		for name, verify := range map[string]func() error{
			"cached query": query, "replay": plan.headerPlanningRecheck,
			"next phase": func() error { return verifyDiscoveryOrdinaryDependencySnapshots(plan) },
		} {
			if err := verify(); err == nil {
				t.Errorf("%s lost original planning-only dependency membership", name)
			}
		}
	})
	for name, file := range map[string]string{
		"asset": filepath.Join(actualForeign.Dir, "asset.bin"), "ZIP": actualForeign.Zip, "metadata": actualForeign.GoMod,
	} {
		t.Run(name, func(t *testing.T) {
			before, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(file, 0600); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.WriteFile(file, before, 0600); err != nil {
					t.Error(err)
				}
			})
			if err := os.WriteFile(file, append(append([]byte(nil), before...), []byte("changed")...), 0600); err != nil {
				t.Fatal(err)
			}
			if err := query(); err == nil {
				t.Error("cached planning query forgot its actual ordinary dependency owner")
			}
			if err := plan.headerPlanningRecheck(); err == nil {
				t.Error("final planning replay forgot its original dependency bytes")
			}
			if err := verifyDiscoveryOrdinaryDependencySnapshots(plan); err == nil {
				t.Error("next execution phase lacks the planning-only dependency guard")
			}
		})
	}
	if err := query(); err != nil || plan.headerPlanningQueryStarts != 1 {
		t.Fatalf("restored unchanged owner lost exact cached-query semantics: %v", err)
	}
	cancel()
	if err := query(); err == nil || verifyDiscoveryOrdinaryDependencySnapshots(plan) == nil {
		t.Fatal("closed planning context retained source authority")
	}
}
