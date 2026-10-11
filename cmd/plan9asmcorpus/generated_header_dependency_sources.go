package main

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

type discoveryOrdinaryDependencyGuard struct {
	Context          context.Context
	Source           gotoolprofile.ModuleSourceSnapshot
	Root, ZIP, GoMod string
	ObservedRoot     string
}

func (guard discoveryOrdinaryDependencyGuard) verify() error {
	root, err := discoveryOrdinaryDependencyRoot(guard.ObservedRoot)
	if err != nil || root != guard.Root {
		return fmt.Errorf("ordinary dependency observed source root changed")
	}
	if err := gotoolprofile.VerifyTestModuleSource(guard.Context, guard.Source, guard.Root, guard.ZIP); err != nil {
		return err
	}
	if guard.Source.SourceModule != "" {
		return gotoolprofile.VerifyTestModuleGoModMetadata(guard.Source, guard.Root, guard.GoMod, guard.GoMod)
	}
	return nil
}

// Canonicalization is not permission to follow a source-internal alias. The
// strict inventory verifier still checks every member under this exact root;
// the live guard additionally retains the original driver/download spelling.
func discoveryOrdinaryDependencyRoot(observed string) (string, error) {
	if !filepath.IsAbs(observed) || filepath.Clean(observed) != observed {
		return "", fmt.Errorf("ordinary dependency lacks an absolute original source root")
	}
	return filepath.EvalSymlinks(observed)
}

func retainDiscoveryOrdinaryDependencyGuard(plan *discoveryOrdinarySelectionPlan, guard discoveryOrdinaryDependencyGuard) error {
	if guard.ObservedRoot == "" {
		guard.ObservedRoot = guard.Root
	}
	for _, previous := range plan.ordinaryDependencyGuards {
		if previous.Root == guard.Root && previous.ObservedRoot == guard.ObservedRoot &&
			previous.ZIP == guard.ZIP && previous.GoMod == guard.GoMod && reflect.DeepEqual(previous.Source, guard.Source) {
			// Profiles can have identical original source inventories. Retain
			// one immutable witness, but still verify the current live bytes.
			return guard.verify()
		}
	}
	// Do not let a mutable portable report projection change the live guard.
	data, err := json.Marshal(guard.Source)
	if err != nil {
		return err
	}
	var frozen gotoolprofile.ModuleSourceSnapshot
	if err := json.Unmarshal(data, &frozen); err != nil {
		return err
	}
	guard.Source = frozen
	if err := guard.verify(); err != nil {
		return err
	}
	plan.ordinaryDependencyGuards = append(plan.ordinaryDependencyGuards, guard)
	return nil
}

func verifyDiscoveryOrdinaryDependencySnapshots(plan *discoveryOrdinarySelectionPlan) error {
	for _, guard := range plan.ordinaryDependencyGuards {
		guard.Context = plan.ordinaryDependencyContext
		if err := guard.verify(); err != nil {
			return err
		}
	}
	return nil
}

// The query process cannot turn self-consistent recorded hashes into original
// source evidence. Independently bind all candidate/dependency bytes to the
// actual downloaded ZIP or the same-profile driver's observed source root.
func verifyDiscoveryOrdinaryDependencies(ctx context.Context, plan *discoveryOrdinarySelectionPlan, download moduleDownloadInfo, proof *gotoolprofile.OrdinaryDependencyProof, dir string, env []string) error {
	plan.ordinaryDependencyContext = ctx
	if proof == nil || proof.Protocol != gotoolprofile.OrdinaryDependencyProtocol {
		return fmt.Errorf("ordinary metadata query lacks dependency source evidence")
	}
	root, err := discoveryOrdinaryDependencyRoot(download.Dir)
	if err != nil {
		return err
	}
	if err := gotoolprofile.VerifySourceInventory(ctx, proof.Candidate, root); err != nil {
		return err
	}
	if err := verifyDiscoveryOriginalSourceMap(plan, download.Dir, download.Zip, proof.Candidate.Sources); err != nil {
		return err
	}
	// This also checks complete original directory membership, not merely the
	// query's positive source/asset list. The existing module verifier retains
	// ZIP h1, archive bytes and original-versus-proxy go.mod separation.
	candidate := gotoolprofile.ModuleSourceSnapshot{
		Protocol: gotoolprofile.TestDependencyModuleProtocol, SourceModule: plan.Module, SourceVersion: plan.Version,
		ModuleSum: plan.ModuleSum, ZipSHA256: plan.ZipSHA256, GoModSum: download.GoModSum,
		Sources: proof.Candidate.Sources, Headers: proof.Candidate.Headers, Directories: proof.Candidate.Directories,
		GoModOrigin: gotoolprofile.TestModuleOriginalGoModOrigin,
	}
	candidate.GoModSHA256, err = gotoolprofile.FileSHA256(download.GoMod)
	if err != nil {
		return err
	}
	if plan.ProxyGoMod != nil {
		candidate.GoModOrigin, candidate.ProxyGoMod = gotoolprofile.ProxyGoModProtocol, plan.ProxyGoMod
	}
	if err := retainDiscoveryOrdinaryDependencyGuard(plan, discoveryOrdinaryDependencyGuard{
		Context: ctx, Source: candidate, Root: root, ObservedRoot: download.Dir, ZIP: download.Zip, GoMod: download.GoMod,
	}); err != nil {
		return err
	}
	for _, source := range proof.SourceModules {
		var root, archive, goMod string
		if source.SourceModule == "" {
			data, _, err := runDiscoveryMachineCommand(ctx, dir, env, "go", "env", "GOROOT")
			if err != nil {
				return err
			}
			root = filepath.Join(strings.TrimSpace(string(data)), "src")
		} else {
			data, _, err := runDiscoveryMachineCommand(ctx, dir, env, "go", "mod", "download", "-json", source.ID())
			if err != nil {
				return err
			}
			var actual moduleDownloadInfo
			if err := json.Unmarshal(data, &actual); err != nil || actual.Path != source.SourceModule || actual.Version != source.SourceVersion ||
				actual.Sum != source.ModuleSum || actual.GoModSum != source.GoModSum {
				return fmt.Errorf("ordinary dependency producer download differs from query identity")
			}
			root, archive = actual.Dir, actual.Zip
			goMod = actual.GoMod
			if err := gotoolprofile.VerifyTestModuleGoModMetadata(source, root, actual.GoMod, actual.GoMod); err != nil {
				return err
			}
		}
		observedRoot := root
		root, err = discoveryOrdinaryDependencyRoot(observedRoot)
		if err != nil {
			return err
		}
		if err := retainDiscoveryOrdinaryDependencyGuard(plan, discoveryOrdinaryDependencyGuard{
			Context: ctx, Source: source, Root: root, ObservedRoot: observedRoot, ZIP: archive, GoMod: goMod,
		}); err != nil {
			return err
		}
	}
	return nil
}
