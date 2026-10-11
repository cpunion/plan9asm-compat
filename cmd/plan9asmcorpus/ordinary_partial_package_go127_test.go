//go:build go1.27

package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestOrdinaryProducerPartialAsmDeclKeepsCompletePackageSelection(t *testing.T) {

	compilerEnvironment := os.Environ()
	candidate := discoveryCandidate{
		Module: "example.invalid/partial-package", Version: "v1.0.0",
		AsmFiles: []string{"bad_amd64.s", "good_amd64.s"},
	}
	sources := map[string]string{
		"go.mod":       "module example.invalid/partial-package\n\ngo 1.20\n",
		"probe.go":     "package partial\nfunc Bad(x uint64) uint64\nfunc Good() uint64\n",
		"bad_amd64.s":  "TEXT ·Bad(SB),4,$0-8\nMOVQ x+0(FP),AX\nMOVQ AX,ret+8(FP)\nRET\n",
		"good_amd64.s": "TEXT ·Good(SB),4,$0-8\nMOVQ $7,ret+0(FP)\nRET\n",
	}
	download := fixtureProfileModuleDownload(t, candidate, sources)
	proxy := t.TempDir()
	versions := filepath.Join(proxy, candidate.Module, "@v")
	if err := os.MkdirAll(versions, 0755); err != nil {
		t.Fatal(err)
	}
	archive, err := os.ReadFile(download.Zip)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"v1.0.0.mod":  []byte(sources["go.mod"]),
		"v1.0.0.info": []byte(`{"Version":"v1.0.0","Time":"2026-10-02T00:00:00Z"}`),
		"v1.0.0.zip":  archive,
	} {
		if err := os.WriteFile(filepath.Join(versions, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("GOPROXY", "file://"+proxy)
	t.Setenv("GOSUMDB", "off")
	t.Setenv("GOMODCACHE", filepath.Join(t.TempDir(), "modules"))
	root, err := fixtureTranslatorRoot()
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "plan9asmll")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "build", "-p=1", "-o", binary, ".")
	command.Dir, command.Env = filepath.Join(root, "cmd", "plan9asmll"), compilerEnvironment
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build our translator: %v\n%s", err, output)
	}
	llc, err := exec.LookPath("llc")
	if err != nil {
		t.Fatal(err)
	}
	matrix, _, configs, err := runDiscoveryCandidate(discoveryCorpusConfig{
		RepoRoot: root, Translator: binary, LLC: llc, Targets: []string{"linux/amd64"},
		CandidateTimeout: time.Minute,
	}, candidate, filepath.Join(t.TempDir(), "candidate"))
	if err != nil {
		t.Fatal(err)
	}
	if matrix.Success != 1 || len(matrix.SourceNotApplicableItems) != 1 || len(configs) != 1 ||
		!equalDiscoveryStrings(configs[0].AsmFiles, []string{"good_amd64.s"}) || len(matrix.FeatureConsumption) != 1 {
		t.Fatalf("partial asmdecl exclusion changed the translated denominator: %#v", matrix)
	}
	proof := matrix.FeatureConsumption[0]
	if len(proof.Packages) != 1 || !equalDiscoveryStrings(proof.Packages[0].SFiles, candidate.AsmFiles) {
		t.Fatal("actual Go-selected assembly was filtered to conceal the rejected sibling")
	}
	inventory := &discoveryFeatureInventory{}
	refs, err := registerDiscoveryFeatureProfiles(inventory, matrix.FeatureProfiles)
	if err != nil {
		t.Fatal(err)
	}
	result := discoveryCorpusResult{
		Module: candidate.Module, Version: candidate.Version, Status: discoveryStatusPassed,
		DiscoveredAsmFiles: candidate.AsmFiles, ApplicableAsmFiles: discoveryConfigurationAsmFiles(configs),
		BuildConfigurations: configs, Translations: matrix.Success,
		SourceNotApplicableItems: matrix.SourceNotApplicableItems,
		OrdinarySelectionPlan:    matrix.OrdinarySelectionPlan, FeatureProfiles: refs,
		FeatureConsumption: matrix.FeatureConsumption,
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	replay := func(data []byte) discoveryCorpusResult {
		t.Helper()
		var copied discoveryCorpusResult
		if err := json.Unmarshal(data, &copied); err != nil {
			t.Fatal(err)
		}
		copied.featureInventory = inventory
		return copied
	}
	validate := func(result discoveryCorpusResult) error {
		return validateOrdinaryProfileResult(result, []string{"linux/amd64"}, matrix.OrdinarySelectionPlan.GoVersion)
	}
	if err := validate(replay(encoded)); err != nil {
		t.Fatalf("actual partial-package proof JSON replay: %v", err)
	}
	for name, change := range map[string]func(*discoveryCorpusResult){
		"missing complete registration": func(r *discoveryCorpusResult) { r.FeatureConsumption[0].RegisteredAsmFiles = nil },
		"unregistered nonempty sibling": func(r *discoveryCorpusResult) { r.FeatureConsumption[0].RegisteredAsmFiles = []string{"good_amd64.s"} },
		"registration alone":            func(r *discoveryCorpusResult) { r.FeatureConsumption = nil },
		"no source diagnostic":          func(r *discoveryCorpusResult) { r.SourceNotApplicableItems = nil },
		"wrong diagnostic tags":         func(r *discoveryCorpusResult) { r.SourceNotApplicableItems[0].BuildTags = []string{"alternate"} },
		"wrong diagnostic profile":      func(r *discoveryCorpusResult) { r.SourceNotApplicableItems[0].ProfileID = "wrong" },
		"wrong package role":            func(r *discoveryCorpusResult) { r.FeatureConsumption[0].Packages[0].SourceRole = "owned_local_replace" },
		"wrong selected hash": func(r *discoveryCorpusResult) {
			r.FeatureConsumption[0].Packages[0].SourceSHA256["bad_amd64.s"] = discoveryFeatureBytesSHA256([]byte("changed"))
		},
		"concealed selected sibling": func(r *discoveryCorpusResult) {
			r.FeatureConsumption[0].Packages[0].SFiles = []string{"good_amd64.s"}
			delete(r.FeatureConsumption[0].Packages[0].SourceSHA256, "bad_amd64.s")
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := replay(encoded)
			change(&changed)
			if err := validate(changed); err == nil {
				t.Fatal("incomplete/changed package registration or scope discharge accepted")
			}
		})
	}
	// Removing an independently selected nonempty file from the explicit
	// translation input still fails without complete package registration.
	profile := matrix.FeatureProfiles[0]
	input := ordinaryProfileConsumerInput(matrix.OrdinarySelectionPlan, profile, candidate.Module, "", []string{"good_amd64.s"})
	input.AsmFiles = nil
	if err := gotoolprofile.ValidateSelection(input, proof, nil, true); err == nil {
		t.Fatal("source registration was mistaken for an executed translation")
	}
}
