package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestTestDependencyLegacySnapshotKeepsIndependentMetadataRole(t *testing.T) {
	proof := fixtureAuthenticatedProxyGoMod(t)
	archive := filepath.Join(t.TempDir(), "unauthenticated-fixture.zip")
	metadata := filepath.Join(t.TempDir(), "authenticated-proxy.mod")
	if err := os.WriteFile(archive, []byte("not the signed module archive"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metadata, []byte(proof.Contents), 0600); err != nil {
		t.Fatal(err)
	}
	metadata, err := filepath.EvalSymlinks(metadata)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("package fixture\n")
	digest := discoveryFeatureBytesSHA256(data)
	capture := &discoveryTestModuleCapture{
		Download: moduleDownloadInfo{Zip: archive, Sum: proof.ModuleSum, GoModSum: proof.GoModSum},
		Plan: &discoveryOrdinarySelectionPlan{
			Module: proof.Module, Version: proof.Version, ProxyGoMod: proof, proxyGoModPath: metadata,
			TestDeclarationDirectories: []ordinarySelectionDirectory{{
				Directory: ".", Entries: []ordinarySelectionEntry{{Name: "fixture.go", Kind: "file", SHA256: digest}},
			}},
			TestDeclarationSources: []ordinarySelectionSource{{File: "fixture.go", Header: string(data), SHA256: digest}},
		},
	}
	// This models only capture/metadata accounting. The actual archive is
	// deliberately unauthenticated and cannot pass the production ZIP guard.
	source, err := discoveryTestModuleSnapshot(capture)
	if err != nil {
		t.Fatal(err)
	}
	if err := gotoolprofile.ValidateTestModuleSource(source); err != nil {
		t.Fatal(err)
	}
	if source.GoModOrigin != proof.Protocol || source.GoModSHA256 != proof.SHA256 || source.ProxyGoMod == nil || source.Sources["go.mod"] != "" {
		t.Fatal("proxy metadata was erased or confused with original ZIP source")
	}
	beforeDirectories := append([]ordinarySelectionDirectory(nil), capture.Plan.TestDeclarationDirectories...)
	beforeSources := append([]ordinarySelectionSource(nil), capture.Plan.TestDeclarationSources...)
	if err := captureDiscoveryTestModuleGoMod(context.Background(), capture, "", nil); err != nil {
		t.Fatal(err)
	}
	if len(capture.Plan.Directories) != 0 || len(capture.Plan.Sources) != 0 ||
		!reflect.DeepEqual(beforeDirectories, capture.Plan.TestDeclarationDirectories) ||
		!reflect.DeepEqual(beforeSources, capture.Plan.TestDeclarationSources) {
		t.Fatal("the authentication helper duplicated/changed actual original source roles")
	}
	dependency := &gotoolprofile.TestDependencyProof{
		SourceModules:    []gotoolprofile.TestModuleSource{source},
		ExternalPackages: []gotoolprofile.TestSourcePackage{{SourceRootID: source.ID()}},
	}
	if err := bindDiscoveryTestModuleMetadataPackages(dependency); err != nil {
		t.Fatal(err)
	}
	pkg := dependency.ExternalPackages[0].Package
	if pkg.GoModOrigin != proof.Protocol || pkg.GoModSHA256 != proof.SHA256 || pkg.GoModSum != proof.GoModSum {
		t.Fatal("actual source-only package lost its distinct signed metadata origin")
	}
	if err := os.WriteFile(metadata, []byte("module example.invalid/changed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := captureDiscoveryTestModuleGoMod(context.Background(), capture, "", nil); err == nil {
		t.Fatal("changed independent metadata passed the final authentication guard")
	}
}

func TestTestDependencyLegacyRepeatedActualMetadataCannotDisappear(t *testing.T) {
	proof := fixtureAuthenticatedProxyGoMod(t)
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	metadata := filepath.Join(t.TempDir(), "proxy.mod")
	export := filepath.Join(t.TempDir(), "owned-export.a")
	for name, data := range map[string]string{
		filepath.Join(root, "fixture.go"): "package fixture\n",
		metadata:                          proof.Contents, export: "owned export fixture",
	} {
		if err := os.WriteFile(name, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	metadata, err = filepath.EvalSymlinks(metadata)
	if err != nil {
		t.Fatal(err)
	}
	capture := &discoveryTestModuleCapture{
		Root:     root,
		Download: moduleDownloadInfo{GoMod: metadata, Sum: proof.ModuleSum, GoModSum: proof.GoModSum},
		Plan: &discoveryOrdinarySelectionPlan{
			Module: proof.Module, Version: proof.Version, ProxyGoMod: proof, proxyGoModPath: metadata,
		},
		Metadata: map[string]string{metadata: proof.SHA256}, Exports: make(map[string]string),
	}
	pkg := gotoolprofile.PackageProof{
		SourceModule: proof.Module, SourceVersion: proof.Version, SourceRole: "module",
	}
	actual := discoverySelectedTestPackage{
		Dir: root, Export: export, Module: &discoverySelectedTestModule{GoMod: metadata},
	}
	captures := map[string]*discoveryTestModuleCapture{proof.Module + "@" + proof.Version: capture}
	// Only the repeat transition is modeled here. Authenticating this owned
	// source/export fixture as the public module would still fail its ZIP guard.
	if _, _, err := captureDiscoveryForeignTestDirectory(context.Background(), captures, actual, pkg, root, "go1.27.1", "", nil); err != nil {
		t.Fatal(err)
	}
	actual.Module.GoMod = ""
	if _, _, err := captureDiscoveryForeignTestDirectory(context.Background(), captures, actual, pkg, root, "go1.27.1", "", nil); err == nil {
		t.Fatal("repeated actual Module.GoMod disappeared without a producer failure")
	}
}
