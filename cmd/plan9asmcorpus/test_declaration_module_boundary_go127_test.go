//go:build go1.27

package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestTestDeclarationDependencyProducerNestedModuleBoundary(t *testing.T) {

	compilerEnv := os.Environ()
	candidate := discoveryCandidate{
		Module: "example.invalid/testboundary", Version: "v1.0.0",
		AsmFiles: []string{"probe_amd64.s"},
	}
	sources := map[string]string{
		"go.mod":        "module example.invalid/testboundary\n\ngo 1.20\nrequire example.invalid/testboundary/loader v1.0.0\n",
		"probe.go":      "package boundary\n",
		"probe_test.go": "package boundary\nimport \"example.invalid/testboundary/loader\"\nfunc probe(x loader.Float) loader.Float\n",
		"probe_amd64.s": "#include \"textflag.h\"\nTEXT ·probe(SB),NOSPLIT,$0-12\nMOVSS x+0(FP),X0\nMOVSS X0,ret+8(FP)\nRET\n",
	}
	download := fixtureProfileModuleDownload(t, candidate, sources)
	installGeneratedFixtureProxy(t, candidate, download, sources["go.mod"])

	external := discoveryCandidate{Module: candidate.Module + "/loader", Version: "v1.0.0"}
	externalSources := map[string]string{
		"go.mod":                              "module example.invalid/testboundary/loader\n\ngo 1.20\n",
		"layout.go":                           "package loader\nimport \"example.invalid/testboundary/loader/internal/layout\"\ntype Float = layout.Float\n",
		"internal/layout/type.go":             "package layout\nimport \"math\"\nimport _ \"embed\"\n//go:embed assets\nvar Data []byte\nconst Pi = math.Pi\ntype Float = float32\n",
		"internal/layout/assets/defaults.bin": "exact original embedded bytes",
	}
	externalDownload := fixtureProfileModuleDownload(t, external, externalSources)
	proxy := strings.TrimPrefix(os.Getenv("GOPROXY"), "file://")
	versions := filepath.Join(proxy, external.Module, "@v")
	if err := os.MkdirAll(versions, 0755); err != nil {
		t.Fatal(err)
	}
	archive, err := os.ReadFile(externalDownload.Zip)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		external.Version + ".mod":  []byte(externalSources["go.mod"]),
		external.Version + ".info": []byte(`{"Version":"v1.0.0","Time":"2026-10-01T00:00:00Z"}`),
		external.Version + ".zip":  archive,
	} {
		if err := os.WriteFile(filepath.Join(versions, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}

	root, err := fixtureTranslatorRoot()
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "plan9asmll")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "build", "-p=1", "-o", binary, ".")
	command.Dir, command.Env = filepath.Join(root, "cmd", "plan9asmll"), compilerEnv
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build owned translator: %v\n%s", err, output)
	}
	llc, err := exec.LookPath("llc")
	if err != nil {
		t.Fatal(err)
	}
	targets := []string{"linux/amd64"}
	matrix, _, configs, err := runDiscoveryCandidate(discoveryCorpusConfig{
		RepoRoot: root, Translator: binary, LLC: llc, Targets: targets,
		CandidateTimeout: 3 * time.Minute,
	}, candidate, filepath.Join(t.TempDir(), "candidate"))
	if err != nil {
		t.Fatalf("actual separate nested-module test import: %v", err)
	}
	if matrix.Success != 1 || len(matrix.FeatureConsumption) != 1 {
		t.Fatalf("external source/type metadata is not an extra translation: %#v", matrix)
	}
	dependency := matrix.OrdinarySelectionPlan.TestDeclarationQueries[0].Dependency
	if len(dependency.Packages) != 1 || len(dependency.SourceModules) != 2 || len(dependency.ExternalPackages) < 3 {
		t.Fatal("separate module, transitive pure-Go and actual stdlib source roles were not retained")
	}
	var loader, layout, mathPackage bool
	for _, source := range dependency.ExternalPackages {
		loader = loader || source.Package.PackagePath == external.Module && source.Package.ModulePath == external.Module
		if source.Package.PackagePath == external.Module+"/internal/layout" && source.Package.ModulePath == external.Module {
			layout = source.Embed != nil && reflect.DeepEqual(source.Embed.Patterns, []string{"assets"}) &&
				source.Embed.Files["internal/layout/assets/defaults.bin"] == discoveryFeatureBytesSHA256([]byte(externalSources["internal/layout/assets/defaults.bin"]))
		}
		mathPackage = mathPackage || source.Package.PackagePath == "math" && source.Package.SourceRole == "stdlib"
	}
	if !loader || !layout || !mathPackage {
		t.Fatal("path prefix was substituted for actual Module/stdlib source selection")
	}
	inventory := newDiscoveryFeatureInventory()
	refs, err := registerDiscoveryFeatureProfiles(inventory, matrix.FeatureProfiles)
	if err != nil {
		t.Fatal(err)
	}
	result := discoveryCorpusResult{
		Module: candidate.Module, Version: candidate.Version, Status: discoveryStatusPassed,
		DiscoveredAsmFiles: candidate.AsmFiles, ApplicableAsmFiles: candidate.AsmFiles,
		BuildConfigurations: configs, Translations: matrix.Success,
		OrdinarySelectionPlan: matrix.OrdinarySelectionPlan, FeatureProfiles: refs,
		FeatureConsumption: matrix.FeatureConsumption,
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var replay discoveryCorpusResult
	if err := json.Unmarshal(encoded, &replay); err != nil {
		t.Fatal(err)
	}
	replay.featureInventory = inventory
	if err := validateOrdinaryProfileResult(replay, targets, matrix.OrdinarySelectionPlan.GoVersion); err != nil {
		t.Fatalf("strict independent nested-module source-boundary reader: %v", err)
	}
	assertTestModuleSemanticProjection(t, replay, inventory)
	for name, mutate := range map[string]func(*gotoolprofile.TestDependencyProof){
		"paired embed role deletion": func(d *gotoolprofile.TestDependencyProof) {
			for i := range d.ExternalPackages {
				d.ExternalPackages[i].Embed = nil
			}
		},
		"paired old source v2": func(d *gotoolprofile.TestDependencyProof) {
			d.Protocol = "actual_go_test_declaration_source_closure_v2"
		},
		"changed embed patterns": func(d *gotoolprofile.TestDependencyProof) {
			for i := range d.ExternalPackages {
				if len(d.ExternalPackages[i].Embed.Patterns) != 0 {
					d.ExternalPackages[i].Embed.Patterns = []string{"different"}
				}
			}
		},
		"changed embed bytes": func(d *gotoolprofile.TestDependencyProof) {
			for i := range d.ExternalPackages {
				for file := range d.ExternalPackages[i].Embed.Files {
					d.ExternalPackages[i].Embed.Files[file] = strings.Repeat("a", 64)
				}
			}
		},
		"old source root protocol": func(d *gotoolprofile.TestDependencyProof) {
			for i := range d.SourceModules {
				d.SourceModules[i].Protocol = "actual_go_test_dependency_module_sources_v1"
			}
		},
		"paired metadata origin deletion": func(d *gotoolprofile.TestDependencyProof) {
			for i := range d.SourceModules {
				d.SourceModules[i].GoModOrigin, d.SourceModules[i].ProxyGoMod = "", nil
			}
			for i := range d.ExternalPackages {
				pkg := &d.ExternalPackages[i].Package
				pkg.GoModOrigin, pkg.GoModSHA256, pkg.GoModSum = "", "", ""
			}
		},
		"unknown metadata origin": func(d *gotoolprofile.TestDependencyProof) {
			for i := range d.SourceModules {
				if d.SourceModules[i].SourceModule != "" {
					d.SourceModules[i].GoModOrigin = "local_metadata"
				}
			}
		},
		"missing boundary roots":    func(d *gotoolprofile.TestDependencyProof) { d.SourceModules = nil },
		"missing external packages": func(d *gotoolprofile.TestDependencyProof) { d.ExternalPackages = nil },
		"missing transitive external node": func(d *gotoolprofile.TestDependencyProof) {
			for i, source := range d.ExternalPackages {
				if source.Package.PackagePath == external.Module+"/internal/layout" {
					d.ExternalPackages = append(d.ExternalPackages[:i], d.ExternalPackages[i+1:]...)
					break
				}
			}
		},
		"foreign relabeled main": func(d *gotoolprofile.TestDependencyProof) { d.ExternalPackages[0].SourceRootID = "" },
		"changed stdlib Go version": func(d *gotoolprofile.TestDependencyProof) {
			for i := range d.SourceModules {
				if d.SourceModules[i].SourceModule == "" {
					d.SourceModules[i].GoVersion = "go1.27.0"
				}
			}
		},
		"unbound export bytes":     func(d *gotoolprofile.TestDependencyProof) { d.ExternalPackages[0].ExportSHA256 = "" },
		"different source version": func(d *gotoolprofile.TestDependencyProof) { d.ExternalPackages[0].Package.SourceVersion = "v1.0.1" },
		"different package metadata role": func(d *gotoolprofile.TestDependencyProof) {
			for i := range d.ExternalPackages {
				if d.ExternalPackages[i].Package.SourceModule != "" {
					d.ExternalPackages[i].Package.GoModOrigin = gotoolprofile.ProxyGoModProtocol
				}
			}
		},
		"unknown import boundary": func(d *gotoolprofile.TestDependencyProof) {
			d.Packages[0].ImportMap[external.Module] = "other.invalid/unbound"
		},
		"old source protocol": func(d *gotoolprofile.TestDependencyProof) {
			d.Protocol = "actual_go_test_declaration_source_closure_v1"
		},
		"changed current consumer export": func(d *gotoolprofile.TestDependencyProof) {
			for i := range d.ExternalPackages {
				if d.ExternalPackages[i].Package.PackagePath == external.Module {
					d.ExternalPackages[i].ExportSHA256 = strings.Repeat("c", 64)
				}
			}
		},
		"builtin role deleted": func(d *gotoolprofile.TestDependencyProof) {
			for i := range d.ExternalPackages {
				if d.ExternalPackages[i].Package.PackagePath == "unsafe" {
					d.ExternalPackages[i].Builtin = ""
				}
			}
		},
		"ordinary dependency disguised as builtin": func(d *gotoolprofile.TestDependencyProof) {
			d.ExternalPackages[0].Builtin = "go_typechecker_unsafe_v1"
		},
	} {
		t.Run(name, func(t *testing.T) {
			var current discoveryCorpusResult
			if err := json.Unmarshal(encoded, &current); err != nil {
				t.Fatal(err)
			}
			current.featureInventory = inventory
			// Agreement alone must not authorize deletion or a changed boundary.
			mutate(current.OrdinarySelectionPlan.TestDeclarationQueries[0].Dependency)
			mutate(current.FeatureConsumption[0].TestDependencies)
			if err := validateOrdinaryProfileResult(current, targets, matrix.OrdinarySelectionPlan.GoVersion); err == nil {
				t.Fatal("reader accepted a changed/truncated module/import/source boundary")
			}
		})
	}
}
