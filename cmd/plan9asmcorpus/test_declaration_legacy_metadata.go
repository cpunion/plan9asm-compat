package main

import (
	"context"
	"fmt"
	"path"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func captureDiscoveryTestModuleGoMod(ctx context.Context, capture *discoveryTestModuleCapture, dir string, env []string) error {
	if capture.Plan.Module == "" {
		return nil
	}
	// Reuse the ordinary authenticated metadata producer, but only with the
	// actual foreign root's complete related directory capture. Its proxy
	// bytes remain outside both original source and directory inventories.
	plan := discoveryTestModuleProxyPlan(capture)
	if plan.ProxyGoMod == nil {
		if err := captureDiscoveryProxyGoMod(ctx, &plan, capture.Download, dir, env); err != nil {
			return fmt.Errorf("authenticate legacy test dependency metadata %s@%s: %w", plan.Module, plan.Version, err)
		}
	}
	capture.Plan.ProxyGoMod, capture.Plan.proxyGoModPath = plan.ProxyGoMod, plan.proxyGoModPath
	return verifyDiscoveryProxyGoMod(&plan)
}

// The ordinary helper sees a separate inventory view. Do not give the same
// directory/header two ordinary/test roles in the actual foreign capture.
func discoveryTestModuleProxyPlan(capture *discoveryTestModuleCapture) discoveryOrdinarySelectionPlan {
	plan := *capture.Plan
	plan.ModuleSum, plan.Sources = capture.Download.Sum, nil
	for _, directory := range capture.Plan.TestDeclarationDirectories {
		for _, entry := range directory.Entries {
			if entry.Kind == "file" {
				plan.Sources = append(plan.Sources, ordinarySelectionSource{
					File: path.Join(directory.Directory, entry.Name), SHA256: entry.SHA256,
				})
			}
		}
	}
	plan.Directories = capture.Plan.TestDeclarationDirectories
	return plan
}

func bindDiscoveryTestModuleMetadataPackages(dependency *gotoolprofile.TestDependencyProof) error {
	roots := make(map[string]gotoolprofile.TestModuleSource)
	for _, source := range dependency.SourceModules {
		roots[source.ID()] = source
	}
	for index := range dependency.ExternalPackages {
		pkg := &dependency.ExternalPackages[index]
		root, found := roots[pkg.SourceRootID]
		if !found {
			return fmt.Errorf("test dependency metadata lacks its actual source-root identity")
		}
		if root.SourceModule != "" {
			pkg.Package.GoModOrigin = root.GoModOrigin
			pkg.Package.GoModSHA256, pkg.Package.GoModSum = root.GoModSHA256, root.GoModSum
		}
	}
	return nil
}
