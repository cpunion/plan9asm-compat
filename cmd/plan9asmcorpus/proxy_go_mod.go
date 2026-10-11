package main

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func captureDiscoveryProxyGoMod(ctx context.Context, plan *discoveryOrdinarySelectionPlan, download moduleDownloadInfo, dir string, env []string) error {
	for _, source := range plan.Sources {
		if source.File == "go.mod" {
			return nil // Original ZIP metadata remains on the original protocol.
		}
	}
	if download.Path != plan.Module || download.Version != plan.Version || download.GoModSum == "" || !filepath.IsAbs(download.GoMod) {
		return fmt.Errorf("legacy proxy metadata lacks exact Go download identity and GoModSum")
	}
	proof, canonical, err := gotoolprofile.CaptureDownloadedProxyGoMod(ctx, "go", dir, env,
		plan.Module, plan.Version, plan.ModuleSum, download.GoModSum, download.GoMod, nil)
	if err != nil {
		return err
	}
	plan.ProxyGoMod, plan.proxyGoModPath = proof, canonical
	return verifyDiscoveryProxyGoMod(plan)
}

func verifyDiscoveryProxyGoMod(plan *discoveryOrdinarySelectionPlan) error {
	if plan.ProxyGoMod == nil {
		return nil
	}
	if err := validateDiscoveryProxyGoMod(plan); err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(plan.proxyGoModPath)
	if err != nil || resolved != plan.proxyGoModPath {
		return fmt.Errorf("independent proxy metadata is missing or redirected")
	}
	actual, err := gotoolprofile.FileSHA256(resolved)
	if err != nil || actual != plan.ProxyGoMod.SHA256 {
		return fmt.Errorf("independent proxy metadata changed after authentication")
	}
	return nil
}

func validateDiscoveryProxyGoMod(plan *discoveryOrdinarySelectionPlan) error {
	if plan.ProxyGoMod == nil {
		return nil
	}
	for _, source := range plan.Sources {
		if source.File == "go.mod" {
			return fmt.Errorf("proxy metadata cannot impersonate original ZIP go.mod")
		}
	}
	for _, dir := range plan.Directories {
		if dir.Directory == "." {
			for _, entry := range dir.Entries {
				if entry.Name == "go.mod" {
					return fmt.Errorf("proxy metadata conflicts with original module directory inventory")
				}
			}
		}
	}
	proof := plan.ProxyGoMod
	if proof.Module != plan.Module || proof.Version != plan.Version || proof.ModuleSum != plan.ModuleSum {
		return fmt.Errorf("proxy metadata differs from exact original module ZIP identity")
	}
	return gotoolprofile.ValidateProxyGoMod(proof)
}

// Historical producer spelling now shares the neutral authenticated reader.
type discoverySumDBReader = gotoolprofile.SumDBReader

func newDiscoverySumDBReader(ctx context.Context, moduleCache, proxy string) (*discoverySumDBReader, error) {
	return gotoolprofile.NewSumDBReader(ctx, moduleCache, proxy)
}

func readDiscoveryChecksumFile(name string, limit int) ([]byte, error) {
	return gotoolprofile.ReadChecksumFile(name, limit)
}
