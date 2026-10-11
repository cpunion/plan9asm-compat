package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSDKNamespaceCommandRequiresCompleteTwoRootDiagnostic(t *testing.T) {
	pkg, module, version := "cmd/compile/internal/ssa", "cmd", "v1.0.0"
	moduleDir, sdkDir := "module/compile/internal/ssa", "tool/src/cmd/compile/internal/ssa"
	diagnostic := "ambiguous import: found package cmd/compile/internal/ssa in multiple modules:\n\tcmd v1.0.0 (module/compile/internal/ssa)\n\t (tool/src/cmd/compile/internal/ssa)\n"
	if err := validateSDKNamespaceCommand(pkg, module, version, moduleDir, sdkDir, 1, "", diagnostic); err != nil {
		t.Fatal(err)
	}
	for name, changed := range map[string]string{
		"foreign package":         strings.ReplaceAll(diagnostic, pkg, "cmd/foreign"),
		"foreign module root":     strings.ReplaceAll(diagnostic, moduleDir, "other/ssa"),
		"foreign SDK root":        strings.ReplaceAll(diagnostic, sdkDir, "other/ssa"),
		"foreign version":         strings.ReplaceAll(diagnostic, version, "v1.0.1"),
		"third module":            diagnostic + "\tother.invalid/pkg v1.0.0 (other/ssa)\n",
		"duplicate":               diagnostic + diagnostic,
		"trailing source error":   diagnostic + "probe.go:3: undefined: x\n",
		"trailing infrastructure": diagnostic + "go: proxy.golang.org: connection refused\n",
		"partial":                 strings.TrimSuffix(diagnostic, "\n"),
		"wrapper":                 "wrapper: " + diagnostic,
	} {
		t.Run(name, func(t *testing.T) {
			if validateSDKNamespaceCommand(pkg, module, version, moduleDir, sdkDir, 1, "", changed) == nil {
				t.Fatal("partial, mixed or foreign diagnostic accepted")
			}
		})
	}
	for _, code := range []int{-1, 0, 2} {
		if validateSDKNamespaceCommand(pkg, module, version, moduleDir, sdkDir, code, "", diagnostic) == nil {
			t.Fatal("non-source exit accepted")
		}
	}
	if validateSDKNamespaceCommand(pkg, module, version, moduleDir, sdkDir, 1, "partial export", diagnostic) == nil {
		t.Fatal("nonempty export stdout accepted")
	}
}

func TestSDKNamespaceModuleDecoderBindsWholeRecord(t *testing.T) {
	plan := &discoveryOrdinarySelectionPlan{Module: "example.invalid/namespace", Version: "v1.0.0", ModuleSum: "h1:fixture"}
	execution := discoveryExecutionPlan{ModulePath: "cmd"}
	goMod := "module-cache/cache/download/example.invalid/namespace/@v/v1.0.0.mod"
	// Independent literal follows stock Go's documented ModulePublic order.
	raw := strings.ReplaceAll(`{
	"Path": "cmd",
	"Version": "v1.0.0",
	"Replace": {
		"Path": "example.invalid/namespace",
		"Version": "v1.0.0",
		"Dir": "module",
		"GoMod": "$GOMOD",
		"GoVersion": "1.20",
		"Sum": "h1:fixture"
	},
	"Dir": "module",
	"GoMod": "$GOMOD",
	"GoVersion": "1.20"
}
`, "$GOMOD", goMod)
	if _, err := validateSDKNamespaceModule(plan, execution, raw, "module", goMod); err != nil {
		t.Fatal(err)
	}
	for name, changed := range map[string]string{
		"empty":                   "",
		"truncated":               raw[:len(raw)-3],
		"trailing JSON":           raw + "{}",
		"trailing infrastructure": raw + "go: connection refused\n",
		"foreign module":          strings.ReplaceAll(raw, "example.invalid/namespace", "example.invalid/foreign"),
		"foreign version":         strings.ReplaceAll(raw, "v1.0.0", "v1.0.1"),
		"foreign root":            strings.ReplaceAll(raw, "\"module\"", "\"foreign\""),
		"foreign GoMod":           strings.ReplaceAll(raw, goMod, "foreign/go.mod"),
		"foreign checksum":        strings.ReplaceAll(raw, "h1:fixture", "h1:other"),
		"decoder type error":      strings.Replace(raw, "\"cmd\"", "7", 1),
		"unknown field":           strings.Replace(raw, "{\n", "{\n\t\"Error\": \"unknown\",\n", 1),
		"duplicate field":         strings.Replace(raw, "{\n", "{\n\t\"Path\": \"cmd\",\n", 1),
		"case alias":              strings.Replace(raw, "\"Path\"", "\"path\"", 1),
		"explicit null":           strings.Replace(raw, "{\n", "{\n\t\"Time\": null,\n", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := validateSDKNamespaceModule(plan, execution, changed, "module", goMod); err == nil {
				t.Fatal("invalid module-query bytes accepted")
			}
		})
	}
}

func TestSDKNamespaceNilBindingsFailClosed(t *testing.T) {
	if _, _, err := sdkNamespaceExecution(nil, "."); err == nil {
		t.Fatal("nil source plan accepted")
	}
	if validateSDKNamespaceRejection(nil, discoveryFeatureProfile{}, discoverySDKNamespaceRejection{}) == nil {
		t.Fatal("nil target accepted")
	}
	if validateSDKNamespaceRules(discoveryGoLoaderRules{}, nil) == nil {
		t.Fatal("nil target rules accepted")
	}
	if _, err := validateDiscoverySDKNamespaceRejections(nil, nil, nil); err == nil {
		t.Fatal("nil scopes accepted")
	}
	if _, err := validateSDKNamespaceModule(nil, discoveryExecutionPlan{}, "{}", "module", "go.mod"); err == nil {
		t.Fatal("nil module plan accepted")
	}
	if verifyDiscoverySDKNamespaceSources(nil, "") == nil {
		t.Fatal("nil physical guard accepted")
	}
	if _, err := captureSDKNamespaceRejection(context.Background(), nil, discoveryFeatureProfile{}, "", "", "", nil, discoveryPackageGroup{}, nil, nil); err == nil {
		t.Fatal("nil producer plan accepted")
	}
}

func TestSDKNamespacePhysicalMembershipGuard(t *testing.T) {
	root := t.TempDir()
	directory := "src/cmd/namespace-fixture"
	full := filepath.Join(root, filepath.FromSlash(directory))
	if err := os.MkdirAll(full, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(full, "probe.go"), []byte("package fixture\n"), 0644); err != nil {
		t.Fatal(err)
	}
	snapshot, err := captureSDKNamespaceDirectory(root, directory)
	if err != nil {
		t.Fatal(err)
	}
	plan := &discoveryOrdinarySelectionPlan{SDKNamespaceRejections: []discoverySDKNamespaceRejection{{SDKDirectory: snapshot}}}
	if err := verifyDiscoverySDKNamespaceSources(plan, root); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(full, "probe.go"), []byte("package changed\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if verifyDiscoverySDKNamespaceSources(plan, root) == nil {
		t.Fatal("changed original SDK member accepted")
	}
	if err := os.WriteFile(filepath.Join(full, "probe.go"), []byte("package fixture\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(full, "extra.go"), []byte("package fixture\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if verifyDiscoverySDKNamespaceSources(plan, root) == nil {
		t.Fatal("changed SDK directory membership accepted")
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil || strings.Contains(string(encoded), root) {
		t.Fatal("private physical root retained in portable snapshot")
	}
	if _, err := captureSDKNamespaceDirectory(root, "../escape"); err == nil {
		t.Fatal("foreign SDK role read")
	}
}

func TestSDKNamespaceUnprovedFailureCannotBecomeGenericSourceNA(t *testing.T) {
	group := discoveryPackageGroup{Pattern: "cmd/compile/internal/ssa", AsmFiles: []string{"probe.s"}}
	failure := &discoveryCapturedCommandError{command: "go list -export", cause: errors.New("fixture failure"), output: "ambiguous import: found package cmd/compile/internal/ssa in multiple modules:\n"}
	called := false
	_, err := runDiscoveryPackageChecksWithProof([]discoveryPackageGroup{group}, func([]string) error { return failure }, func(_ discoveryPackageGroup, actual error) (bool, error) {
		called = true
		if !isPotentialSDKNamespaceFailure(actual) {
			t.Fatal("SDK collision lost attribution")
		}
		return false, errors.New("incomplete original root bindings")
	})
	if err == nil || !called {
		t.Fatal("positionless unproved rejection became generic N/A")
	}
}
