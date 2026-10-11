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

func TestTestDeclarationDependencyProducerPureGoAncestors(t *testing.T) {

	compilerEnv := os.Environ()
	candidate := discoveryCandidate{
		Module: "example.invalid/testancestor", Version: "v1.0.0",
		AsmFiles: []string{"nested/child/probe_386.s", "nested/child/probe_amd64.s"},
	}
	sources := map[string]string{
		"go.mod":                     "module example.invalid/testancestor\n\ngo 1.20\n",
		"value.go":                   "package ancestor\ntype Float = float32\n",
		"unused_arm64.go":            "package ancestor\n",
		"nested/value.go":            "package nested\nimport \"example.invalid/testancestor\"\ntype Float = ancestor.Float\n",
		"nested/unused_arm64.go":     "package nested\n",
		"nested/child/probe.go":      "package child\n",
		"nested/child/probe_test.go": "package child\nimport (\"example.invalid/testancestor\"; \"example.invalid/testancestor/nested\")\nfunc probe(x nested.Float) ancestor.Float\n",
		"nested/child/probe_amd64.s": "#include \"textflag.h\"\nTEXT ·probe(SB),NOSPLIT,$0-12\nMOVSS x+0(FP),X0\nMOVSS X0,ret+8(FP)\nRET\n",
		"nested/child/probe_386.s":   "#include \"textflag.h\"\nTEXT ·probe(SB),NOSPLIT,$0-8\nMOVSS x+0(FP),X0\nMOVSS X0,ret+4(FP)\nRET\n",
	}
	download := fixtureProfileModuleDownload(t, candidate, sources)
	installGeneratedFixtureProxy(t, candidate, download, sources["go.mod"])
	targets := []string{"linux/386", "linux/amd64"}
	before, err := captureOrdinarySelectionInputs(candidate, download.Dir, targets)
	if err != nil {
		t.Fatal(err)
	}
	if len(before.Directories) != 3 {
		t.Fatal("fixture must already capture both pure-Go ancestor directories")
	}
	for _, source := range before.Sources {
		if source.File == "value.go" || source.File == "nested/value.go" {
			t.Fatal("ordinary assembly selection must not impersonate a pure-Go dependency role")
		}
	}
	root, err := fixtureTranslatorRoot()
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "plan9asmll")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "build", "-p=2", "-o", binary, ".")
	command.Dir, command.Env = filepath.Join(root, "cmd", "plan9asmll"), compilerEnv
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build owned translator: %v\n%s", err, output)
	}
	llc, err := exec.LookPath("llc")
	if err != nil {
		t.Fatal(err)
	}
	matrix, _, configs, err := runDiscoveryCandidate(discoveryCorpusConfig{
		RepoRoot: root, Translator: binary, LLC: llc, Targets: targets,
		CandidateTimeout: 3 * time.Minute,
	}, candidate, filepath.Join(t.TempDir(), "candidate"))
	if err != nil {
		t.Fatalf("actual test declaration imports original pure-Go ancestors: %v", err)
	}
	plan := matrix.OrdinarySelectionPlan
	if matrix.Success != 2 || len(matrix.FeatureConsumption) != 2 || len(plan.TestDeclarationDirectories) != 0 ||
		len(plan.TestDeclarationSources) != 4 || len(plan.TestDeclarationQueries) != 2 {
		t.Fatalf("ancestor headers must supplement, not replace or duplicate ordinary directories: %#v", matrix)
	}
	if err := verifyDiscoveryTestDependencySources(plan, download.Dir, download.Zip); err != nil {
		t.Fatal(err)
	}
	inventory := newDiscoveryFeatureInventory()
	refs, err := registerDiscoveryFeatureProfiles(inventory, matrix.FeatureProfiles)
	if err != nil {
		t.Fatal(err)
	}
	result := discoveryCorpusResult{
		Module: candidate.Module, Version: candidate.Version, Status: discoveryStatusPassed,
		DiscoveredAsmFiles: candidate.AsmFiles, ApplicableAsmFiles: candidate.AsmFiles,
		BuildConfigurations: configs, Translations: matrix.Success, OrdinarySelectionPlan: plan,
		FeatureProfiles: refs, FeatureConsumption: matrix.FeatureConsumption,
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*discoveryOrdinarySelectionPlan){
		"original":            func(*discoveryOrdinarySelectionPlan) {},
		"no ancestor headers": func(p *discoveryOrdinarySelectionPlan) { p.TestDeclarationSources = nil },
		"omit unselected header": func(p *discoveryOrdinarySelectionPlan) {
			for index, source := range p.TestDeclarationSources {
				if source.File == "unused_arm64.go" {
					p.TestDeclarationSources = append(p.TestDeclarationSources[:index], p.TestDeclarationSources[index+1:]...)
					return
				}
			}
		},
		"changed original source": func(p *discoveryOrdinarySelectionPlan) {
			p.TestDeclarationSources[0].SHA256 = strings.Repeat("a", 64)
		},
		"changed selected ancestor imports": func(p *discoveryOrdinarySelectionPlan) {
			for index := range p.TestDeclarationSources {
				source := &p.TestDeclarationSources[index]
				if source.File == "nested/value.go" {
					source.Header += "import \"missing.invalid\"\n"
					source.HeaderSHA256 = discoveryFeatureBytesSHA256([]byte(source.Header))
					return
				}
			}
		},
		"duplicate original directory": func(p *discoveryOrdinarySelectionPlan) {
			p.TestDeclarationDirectories = append(p.TestDeclarationDirectories, p.Directories[0])
		},
		"ordinary header impersonation": func(p *discoveryOrdinarySelectionPlan) {
			p.TestDeclarationSources = append(p.TestDeclarationSources, p.Sources[len(p.Sources)-1])
		},
		"missing actual dependency": func(p *discoveryOrdinarySelectionPlan) {
			p.TestDeclarationQueries[0].Dependency.Packages = p.TestDeclarationQueries[0].Dependency.Packages[:2]
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var replay discoveryCorpusResult
			if err := json.Unmarshal(encoded, &replay); err != nil {
				t.Fatal(err)
			}
			replay.featureInventory = inventory
			mutate(replay.OrdinarySelectionPlan)
			err := validateOrdinaryProfileResult(replay, targets, plan.GoVersion)
			if name == "original" && err != nil {
				t.Fatalf("actual ancestor source closure JSON replay: %v", err)
			}
			if name != "original" && err == nil {
				t.Fatal("reader accepted missing/changed/duplicate ancestor source proof")
			}
		})
	}
}
