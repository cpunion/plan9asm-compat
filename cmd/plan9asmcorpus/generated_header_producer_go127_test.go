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

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestOrdinaryGeneratedHeaderProducerActualProfilesAndOfflineReplay(t *testing.T) {

	compilerEnv := os.Environ()
	candidate := discoveryCandidate{Module: "example.invalid/generated", Version: "v1.0.0", AsmFiles: []string{"probe_amd64.s"}}
	sources := map[string]string{
		"go.mod":                    "module example.invalid/generated\n\ngo 1.20\n",
		"probe.go":                  "package generated\nimport (\"fmt\"; \"example.invalid/generated/internal/layout\")\nvar _ = fmt.Sprintf\nconst Answer = layout.Answer\ntype Layout struct { Byte byte; Word uint64 }\nfunc probe() uint64\n",
		"values_v3.go":              "//go:build amd64.v3\n\npackage generated\nconst Optional = 3\n",
		"values_v1.go":              "//go:build !amd64.v3\n\npackage generated\nconst Fallback = 1\n",
		"internal/layout/value.go":  "package layout\nimport _ \"embed\"\nconst Answer = 7\n//go:embed asset.bin\nvar Asset []byte\n",
		"internal/layout/asset.bin": "original ordinary dependency asset\n",
		"probe_amd64.s":             "#include \"go_asm.h\"\n#include \"textflag.h\"\n#ifdef const_Never\n#include \"inactive-missing.h\"\n#endif\nTEXT ·probe(SB),NOSPLIT,$0-8\n#ifdef const_Optional\n#ifdef GOAMD64_v3\nMOVQ $const_Optional,ret+0(FP)\n#else\nMOVQ $const_Answer,ret+0(FP)\n#endif\n#else\nMOVQ $const_Fallback,ret+0(FP)\n#endif\nRET\n",
	}
	download := fixtureProfileModuleDownload(t, candidate, sources)
	installGeneratedFixtureProxy(t, candidate, download, sources["go.mod"])
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
	matrix, _, configs, err := runDiscoveryCandidate(discoveryCorpusConfig{
		RepoRoot: root, Translator: binary, LLC: llc, Targets: []string{"linux/amd64"}, CandidateTimeout: 2 * time.Minute,
	}, candidate, filepath.Join(t.TempDir(), "candidate"))
	if err != nil {
		t.Fatal(err)
	}
	plan := matrix.OrdinarySelectionPlan
	if plan != nil && (plan.headerPlanningQueryStarts != 0 || plan.HeaderPlanning != nil) {
		t.Fatalf("known imported planning domain still launched a query or acquired a verified role: starts=%d role=%v", plan.headerPlanningQueryStarts, plan.HeaderPlanning)
	}
	if matrix.Success != 4 || matrix.NotApplicable != 0 || len(matrix.FeatureConsumption) != 4 || len(configs) != 4 || plan == nil || len(plan.GeneratedHeaders) != 4 {
		t.Fatalf("generated header queries must not count as translations or erase latent CPU scopes: %#v", matrix)
	}
	if plan.GeneratedGoSources["internal/layout/value.go"] == "" {
		t.Fatal("same-module non-ASM imported Go source lacks pre-load original ZIP identity")
	}
	for _, proof := range matrix.FeatureConsumption {
		if proof.GeneratedHeaders == nil || len(proof.CPP) != 1 || len(proof.CPP[0].Inputs) != 3 {
			t.Fatalf("missing actual full header or inactive include incorrectly consumed: %#v", proof)
		}
		closure := proof.GeneratedHeaders.Dependencies
		if closure == nil || closure.Candidate.Sources["internal/layout/asset.bin"] != discoveryFeatureBytesSHA256([]byte(sources["internal/layout/asset.bin"])) {
			t.Fatal("ordinary dependency asset lacks its original ZIP source closure")
		}
	}
	inventory := newDiscoveryFeatureInventory()
	refs, err := registerDiscoveryFeatureProfiles(inventory, matrix.FeatureProfiles)
	if err != nil {
		t.Fatal(err)
	}
	result := discoveryCorpusResult{
		Module: candidate.Module, Version: candidate.Version, Status: discoveryStatusPassed,
		DiscoveredAsmFiles: candidate.AsmFiles, ApplicableAsmFiles: candidate.AsmFiles, BuildConfigurations: configs,
		Translations: matrix.Success, OrdinarySelectionPlan: plan, FeatureProfiles: refs, FeatureConsumption: matrix.FeatureConsumption,
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var replayed discoveryCorpusResult
	if err := json.Unmarshal(encoded, &replayed); err != nil {
		t.Fatal(err)
	}
	replayed.featureInventory = inventory
	if err := validateOrdinaryProfileResult(replayed, []string{"linux/amd64"}, plan.GoVersion); err != nil {
		t.Fatalf("full generated/header/profile producer-consumer JSON replay: %v", err)
	}
	mutations := map[string]func(*discoveryCorpusResult){
		"paired dependency role deletion": func(result *discoveryCorpusResult) {
			for index := range result.OrdinarySelectionPlan.GeneratedHeaders {
				result.OrdinarySelectionPlan.GeneratedHeaders[index].Metadata.Dependencies = nil
			}
			for _, proof := range result.FeatureConsumption {
				proof.GeneratedHeaders.Dependencies = nil
			}
		},
		"dependency empty witness deletion": func(result *discoveryCorpusResult) {
			result.OrdinarySelectionPlan.GeneratedHeaders[0].Metadata.Dependencies.Packages[0].Embed = nil
		},
		"transitive ordinary dependency deletion": func(result *discoveryCorpusResult) {
			result.OrdinarySelectionPlan.GeneratedHeaders[0].Metadata.Dependencies.ExternalPackages = nil
		},
		"missing producer query": func(result *discoveryCorpusResult) { result.OrdinarySelectionPlan.GeneratedHeaders = nil },
		"metadata only is not translation": func(result *discoveryCorpusResult) {
			result.FeatureConsumption = nil
			result.Translations = 0
		},
		"changed generated value": func(result *discoveryCorpusResult) {
			header := &result.OrdinarySelectionPlan.GeneratedHeaders[0].Metadata.Headers[0]
			header.Definitions["const_Answer"] = "9"
			header.DefinitionsSHA256 = gotoolprofile.HeaderDefinitionSHA256(header.Definitions)
		},
		"changed generated presence": func(result *discoveryCorpusResult) {
			header := &result.OrdinarySelectionPlan.GeneratedHeaders[0].Metadata.Headers[0]
			header.Definitions["const_Never"] = "1"
			header.DefinitionsSHA256 = gotoolprofile.HeaderDefinitionSHA256(header.Definitions)
		},
		"different import export": func(result *discoveryCorpusResult) {
			result.OrdinarySelectionPlan.GeneratedHeaders[0].Metadata.Headers[0].Imports[0].ExportSHA256 = strings.Repeat("d", 64)
		},
		"different imported original source": func(result *discoveryCorpusResult) {
			result.OrdinarySelectionPlan.GeneratedGoSources["internal/layout/value.go"] = strings.Repeat("e", 64)
		},
		"different actual profile": func(result *discoveryCorpusResult) {
			result.OrdinarySelectionPlan.GeneratedHeaders[0].Metadata.Headers[0].ProfileID = strings.Repeat("f", 64)
		},
		"different package role": func(result *discoveryCorpusResult) {
			result.OrdinarySelectionPlan.GeneratedHeaders[0].Metadata.Packages[0].SourceRole = "main"
		},
		"duplicate query": func(result *discoveryCorpusResult) {
			plan := result.OrdinarySelectionPlan
			plan.GeneratedHeaders = append(plan.GeneratedHeaders, plan.GeneratedHeaders[0])
		},
		"query cannot outlive actual execution": func(result *discoveryCorpusResult) {
			query := result.OrdinarySelectionPlan.GeneratedHeaders[0]
			result.BuildConfigurations = result.BuildConfigurations[1:]
			result.FeatureConsumption = result.FeatureConsumption[1:]
			result.Translations--
			result.SourceNotApplicableItems = []discoverySourceNotApplicableItem{{
				ProfileID: query.ProfileID, BuildTags: query.BuildTags, Targets: []string{query.Target}, AsmFiles: query.AsmFiles,
				Kind: discoverySourceNotApplicableGoBuild, Reason: "probe.go:3:2: undefined: rejected",
			}}
		},
		"old eager protocol cannot claim deferred inputs": func(result *discoveryCorpusResult) {
			result.OrdinarySelectionPlan.CPPInputs.Protocol = discoveryCPPInputsProtocol
		},
		"missing actual active header input": func(result *discoveryCorpusResult) {
			for id := range result.FeatureConsumption[0].CPP[0].Inputs {
				if strings.HasPrefix(id, "generated/") {
					delete(result.FeatureConsumption[0].CPP[0].Inputs, id)
				}
			}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var altered discoveryCorpusResult
			if err := json.Unmarshal(encoded, &altered); err != nil {
				t.Fatal(err)
			}
			altered.featureInventory = inventory
			mutate(&altered)
			if err := validateOrdinaryProfileResult(altered, []string{"linux/amd64"}, plan.GoVersion); err == nil {
				t.Fatal("offline reader accepted altered generated-header source/profile/consumption proof")
			}
		})
	}
}
