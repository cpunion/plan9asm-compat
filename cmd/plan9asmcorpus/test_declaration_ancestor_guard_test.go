package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func ancestorSourceFixture(t *testing.T) (*discoveryOrdinarySelectionPlan, moduleDownloadInfo) {
	t.Helper()
	candidate := discoveryCandidate{
		Module: "example.invalid/ancestorproof", Version: "v1.0.0",
		AsmFiles: []string{"child/probe_amd64.s"},
	}
	download := fixtureProfileModuleDownload(t, candidate, map[string]string{
		"go.mod":              "module example.invalid/ancestorproof\n",
		"value.go":            "package ancestor\ntype Value = uint64\n",
		"value_arm64.go":      "package ancestor\n",
		"guard.h":             "#define ORIGINAL 1\n",
		"child/probe.go":      "package child\n",
		"child/probe_amd64.s": "TEXT ·probe(SB),4,$0-0\nRET\n",
	})
	// The production caller resolves its authenticated module root before
	// capturing directories. macOS t.TempDir may instead spell /var through
	// the /private/var symlink, so give this fixture the same canonical input.
	root, err := filepath.EvalSymlinks(download.Dir)
	if err != nil {
		t.Fatal(err)
	}
	download.Dir = root
	plan, err := captureOrdinarySelectionInputs(candidate, download.Dir, []string{"linux/amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyOrdinarySelectionZIP(plan, download.Zip, candidate.Module, candidate.Version, ""); err != nil {
		t.Fatal(err)
	}
	return plan, download
}

func TestTestDeclarationAncestorSourceCaptureGuard(t *testing.T) {
	plan, download := ancestorSourceFixture(t)
	ordinaryBefore, err := json.Marshal(struct {
		Sources     []ordinarySelectionSource
		Directories []ordinarySelectionDirectory
	}{plan.Sources, plan.Directories})
	if err != nil {
		t.Fatal(err)
	}
	if err := captureDiscoveryTestSourceDirectory(plan, download.Dir, filepath.Join(download.Dir, "child")); err != nil {
		t.Fatal(err)
	}
	ordinaryAfter, err := json.Marshal(struct {
		Sources     []ordinarySelectionSource
		Directories []ordinarySelectionDirectory
	}{plan.Sources, plan.Directories})
	if err != nil || string(ordinaryBefore) != string(ordinaryAfter) || len(plan.TestDeclarationDirectories) != 0 || len(plan.TestDeclarationSources) != 2 {
		t.Fatal("supplemental headers changed or duplicated original ordinary source/directory roles")
	}
	if err := verifyDiscoveryTestDependencySources(plan, download.Dir, download.Zip); err != nil {
		t.Fatal(err)
	}
	before, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := captureDiscoveryTestSourceDirectory(plan, download.Dir, filepath.Join(download.Dir, "child")); err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(plan)
	if err != nil || string(before) != string(after) {
		t.Fatal("repeated dependency capture duplicated or changed original headers")
	}
}

func TestTestDeclarationAncestorRejectsChangedOriginalDirectory(t *testing.T) {
	mutations := map[string]func(*testing.T, string){
		"selected Go bytes": func(t *testing.T, root string) {
			writeTestFile(t, filepath.Join(root, "value.go"), "package ancestor\ntype Value = uint32\n")
		},
		"unselected Go bytes": func(t *testing.T, root string) {
			writeTestFile(t, filepath.Join(root, "value_arm64.go"), "package ancestor\nvar Changed int\n")
		},
		"non-Go bytes": func(t *testing.T, root string) {
			writeTestFile(t, filepath.Join(root, "guard.h"), "#define ORIGINAL 2\n")
		},
		"extra Go member": func(t *testing.T, root string) {
			writeTestFile(t, filepath.Join(root, "late.go"), "package ancestor\n")
		},
		"deleted member": func(t *testing.T, root string) {
			if err := os.Remove(filepath.Join(root, "value_arm64.go")); err != nil {
				t.Fatal(err)
			}
		},
		"nonregular member": func(t *testing.T, root string) {
			if err := os.Symlink("value.go", filepath.Join(root, "late.go")); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			plan, download := ancestorSourceFixture(t)
			mutate(t, download.Dir)
			if err := captureDiscoveryTestSourceDirectory(plan, download.Dir, filepath.Join(download.Dir, "child")); err == nil {
				t.Fatal("existing directory registration hid changed original membership/bytes")
			}
		})
		t.Run("post-load "+name, func(t *testing.T) {
			plan, download := ancestorSourceFixture(t)
			if err := captureDiscoveryTestSourceDirectory(plan, download.Dir, filepath.Join(download.Dir, "child")); err != nil {
				t.Fatal(err)
			}
			mutate(t, download.Dir)
			if err := verifyDiscoveryTestDependencySnapshot(plan, download.Dir); err == nil {
				t.Fatal("changed original ancestor membership/bytes bypassed post-load guard")
			}
		})
	}
}

func TestTestDeclarationAncestorZIPBindsHeaderAndFullSourceSeparately(t *testing.T) {
	plan, download := ancestorSourceFixture(t)
	if err := captureDiscoveryTestSourceDirectory(plan, download.Dir, download.Dir); err != nil {
		t.Fatal(err)
	}
	// A full-source hash alone cannot authenticate arbitrary stored header text.
	// The producer must re-read the original ZIP even if its recorded SHA/h1
	// and the extracted full source have not changed.
	beforeSHA, beforeSum := plan.TestDeclarationSources[0].SHA256, plan.ModuleSum
	plan.TestDeclarationSources[0].Header = "package forged\n"
	plan.TestDeclarationSources[0].HeaderSHA256 = discoveryFeatureBytesSHA256([]byte("package forged\n"))
	if err := verifyDiscoveryTestDependencySources(plan, download.Dir, download.Zip); err == nil {
		t.Fatal("changed header with unchanged full SHA/ZIP h1 bypassed actual ZIP comparison")
	}
	if beforeSHA != plan.TestDeclarationSources[0].SHA256 || beforeSum != plan.ModuleSum {
		t.Fatal("negative fixture did not preserve the original full-source/ZIP identity")
	}
}
