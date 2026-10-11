package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOrdinarySelectionInvalidPackagePath(t *testing.T) {
	const kind = "go_invalid_package_import_path"
	for _, dir := range []string{
		"pkg/mod/github.com/cespare/xxhash/v2@v2.1.1",
		"pkg/has space",
	} {
		t.Run(dir, func(t *testing.T) {
			file := dir + "/native_amd64.s"
			plan := fixtureOrdinarySelection(t, []string{file}, []string{"linux/amd64", "darwin/amd64"}, map[string]string{
				file:             "TEXT ·F(SB),$0-0\nRET\n",
				dir + "/decl.go": "package ordinary\nfunc F()\n",
			})
			decisions, eligible, err := replayOrdinarySelection(plan, []string{file})
			if err != nil {
				t.Fatal(err)
			}
			if len(eligible) != 0 || len(decisions) != 1 || decisions[0].Kind != kind || decisions[0].Boundary != dir {
				t.Fatalf("invalid package path became executable: decisions=%+v eligible=%v", decisions, eligible)
			}
			if !strings.Contains(decisions[0].Diagnostic, "example.com/ordinary/"+dir) {
				t.Fatalf("diagnostic omits the exact rejected import path: %+v", decisions[0])
			}
			result := discoveryCorpusResult{
				Module: plan.Module, Version: plan.Version, Status: discoveryStatusNotApplicable,
				DiscoveredAsmFiles: []string{file}, OrdinarySelectionPlan: plan,
			}
			fixtureProfileEvidence(t, &result, newDiscoveryFeatureInventory())
			if err := validateOrdinarySelectionResult(result, plan.Targets, plan.GoVersion); err != nil {
				t.Fatal(err)
			}
			if err := validateOrdinaryProfileResult(result, plan.Targets, plan.GoVersion); err != nil {
				t.Fatal(err)
			}
			for _, mutation := range []struct {
				name string
				edit func(*discoveryCorpusResult)
			}{
				{"missing decision", func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.ProfileDecisions = nil }},
				{"wrong boundary", func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.ProfileDecisions[0].Boundary = "valid" }},
				{"invented diagnostic", func(r *discoveryCorpusResult) {
					r.OrdinarySelectionPlan.ProfileDecisions[0].Diagnostic = "unknown error"
				}},
				{"unexecuted pass", func(r *discoveryCorpusResult) { r.Status = discoveryStatusPassed; r.Translations = 1 }},
			} {
				t.Run(mutation.name, func(t *testing.T) {
					data, err := json.Marshal(result)
					if err != nil {
						t.Fatal(err)
					}
					var changed discoveryCorpusResult
					if err := json.Unmarshal(data, &changed); err != nil {
						t.Fatal(err)
					}
					changed.featureInventory = result.featureInventory
					mutation.edit(&changed)
					if err := validateOrdinaryProfileResult(changed, plan.Targets, plan.GoVersion); err == nil {
						t.Fatal("reader accepted a forged package-path exclusion")
					}
				})
			}
		})
	}
}

func TestOrdinarySelectionInvalidPackagePathDoesNotExcludeValidSibling(t *testing.T) {
	valid := "normal/native_amd64.s"
	invalid := "pkg/mod/example.com/cached@v1.2.3/native_amd64.s"
	result := fixtureOrdinaryPassedResult(t, discoveryCandidate{
		Module: "example.com/ordinary", Version: "v1.0.0", AsmFiles: []string{valid, invalid},
	}, []string{"linux/amd64"})
	if result.Translations != 1 || !equalDiscoveryStrings(result.ApplicableAsmFiles, []string{valid}) {
		t.Fatalf("invalid directory hid or counted a normal sibling: %+v", result)
	}
	if err := validateOrdinaryProfileResult(result, result.OrdinarySelectionPlan.Targets, result.OrdinarySelectionPlan.GoVersion); err != nil {
		t.Fatal(err)
	}
}

func TestOrdinarySelectionValidPackagePathsRemainEligible(t *testing.T) {
	for _, dir := range []string{".", "pkg/mod/github.com/cespare/xxhash/v2", "pkg/plus+name", "pkg/tilde~name"} {
		t.Run(dir, func(t *testing.T) {
			file := filepath.ToSlash(filepath.Join(dir, "native_amd64.s"))
			plan := fixtureOrdinarySelection(t, []string{file}, []string{"linux/amd64"}, map[string]string{
				file: "TEXT ·F(SB),$0-0\nRET\n",
				filepath.ToSlash(filepath.Join(dir, "decl.go")): "package ordinary\nfunc F()\n",
			})
			if len(plan.Decisions) != 1 || plan.Decisions[0].Kind != nativeLayoutSelected {
				t.Fatalf("valid package path was excluded: %+v", plan.Decisions)
			}
		})
	}
}

func TestOrdinarySelectionPackagePathMatchesActualGo(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	for _, dir := range []string{"valid", "pkg/mod/example.com/cached@v1.2.3"} {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(dir)), 0700); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, filepath.Join(root, filepath.FromSlash(dir), "decl.go"), "package ordinary\nfunc F()\n")
		writeTestFile(t, filepath.Join(root, filepath.FromSlash(dir), "native_amd64.s"), "#include \"textflag.h\"\nTEXT ·F(SB),NOSPLIT,$0-0\nRET\n")
	}
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.com/ordinary\n\ngo 1.20\n")
	env := replaceEnv(os.Environ(), map[string]string{
		"GOWORK": "off", "GOFLAGS": "", "GOTOOLCHAIN": "local", "CGO_ENABLED": "0",
		"GOOS": "linux", "GOARCH": "amd64", "GOPROXY": "off", "GOSUMDB": "off",
		"GOCACHE":    filepath.Join(t.TempDir(), "build"),
		"GOMODCACHE": filepath.Join(t.TempDir(), "mod"),
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	output, _, err := runDiscoveryMachineCommand(ctx, root, env, goBinary, "list", "-export", "-mod=readonly", "./valid")
	if err != nil || strings.TrimSpace(string(output)) != "example.com/ordinary/valid" {
		t.Fatalf("valid sibling did not compile with Go: %v: %s", err, output)
	}
	for _, tc := range []struct {
		argument, diagnostic string
	}{
		{"./pkg/mod/example.com/cached@v1.2.3", "outside main module or its selected dependencies"},
		{"example.com/ordinary/pkg/mod/example.com/cached@v1.2.3", "can only use path@version syntax"},
	} {
		output, stderr, err := runDiscoveryMachineCommand(ctx, root, env, goBinary, "list", "-export", "-mod=readonly", tc.argument)
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() <= 0 || !strings.Contains(string(stderr), tc.diagnostic) {
			t.Fatalf("actual Go did not reject %s: error=%v stdout=%s stderr=%s", tc.argument, err, output, stderr)
		}
	}
}
