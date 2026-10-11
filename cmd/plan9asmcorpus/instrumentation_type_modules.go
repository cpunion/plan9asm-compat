package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/mod/module"
)

// This preflight records only source resources of actual ordinary mode
// dependencies. The shared directory/ZIP helpers create no test-declaration,
// test-selection, embed, eligible assembly, or object role here.
func captureDiscoveryInstrumentationTypeModules(ctx context.Context, binary, directory string, env []string,
	input *gotoolprofile.InstrumentationConsumerInput,
) ([]gotoolprofile.TestModuleSource, error) {
	flags, err := gotoolprofile.InstrumentationPackageLoadFlags(input)
	if err != nil {
		return nil, err
	}
	// This source-only preflight precedes the invocation metadata freeze. Go
	// may resolve its actual MVS graph in the owned invocation, never in the
	// original module. Every later capture/query/object load is readonly.
	for i, flag := range flags {
		if flag == "-mod=readonly" {
			flags[i] = "-mod=mod"
		}
	}
	args := append([]string{"list", "-deps", "-compiled", "-json"}, flags...)
	args = append(args, input.Plan.PackagePath)
	stdout, stderr, err := gotoolprofile.RunBounded(ctx, directory, env, binary, args...)
	if err != nil || len(stdout) == 0 || len(stdout) > 64<<20 {
		return nil, fmt.Errorf("actual instrumentation source-only graph preflight: %v; %s", err, stderr)
	}
	// Only the existing registered cmd/go successful resolver/download
	// notices are admissible here. They grant no source or object authority.
	if err := directAsmDeclValidateSuccessfulStderr(args, string(stderr)); err != nil {
		return nil, err
	}
	captures := make(map[string]*discoveryTestModuleCapture)
	budget := new(discoveryInstrumentationTypeBudget)
	decoder := json.NewDecoder(bytes.NewReader(stdout))
	seen := make(map[string]bool)
	for {
		var actual discoverySelectedTestPackage
		if err := decoder.Decode(&actual); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		if actual.ImportPath == "" || seen[actual.ImportPath] || len(seen) >= 4096 || actual.ForTest != "" || actual.Error != nil || len(actual.DepsErrors) != 0 {
			return nil, fmt.Errorf("instrumentation source-only graph lost complete ordinary package selection")
		}
		seen[actual.ImportPath] = true
		if actual.ImportPath == input.Plan.PackagePath && (actual.Module == nil || actual.Module.Path != input.Original.Module) {
			return nil, fmt.Errorf("instrumentation source-only graph changed its original root owner")
		}
		if actual.Module == nil || actual.Module.Path == input.Original.Module {
			continue
		}
		owner := actual.Module
		if owner.Main || module.Check(owner.Path, owner.Version) != nil {
			return nil, fmt.Errorf("foreign original type source lacks exact module ownership")
		}
		sourceModule, sourceVersion := owner.Path, owner.Version
		root, err := filepath.EvalSymlinks(owner.Dir)
		if err != nil {
			return nil, err
		}
		metadata := owner.GoMod
		if replacement := owner.Replace; replacement != nil {
			if replacement.Main || replacement.Replace != nil || module.Check(replacement.Path, replacement.Version) != nil {
				return nil, fmt.Errorf("foreign original type source has unknown/local/nested replacement")
			}
			replaced, err := filepath.EvalSymlinks(replacement.Dir)
			if err != nil || root != replaced {
				return nil, fmt.Errorf("foreign original type replacement differs from actual directory")
			}
			sourceModule, sourceVersion, metadata = replacement.Path, replacement.Version, replacement.GoMod
		}
		id := sourceModule + "@" + sourceVersion
		capture := captures[id]
		if capture == nil {
			capture = &discoveryTestModuleCapture{Root: root, Plan: &discoveryOrdinarySelectionPlan{Module: sourceModule, Version: sourceVersion},
				Metadata: make(map[string]string), Exports: make(map[string]string)}
			data, _, err := gotoolprofile.RunBounded(ctx, directory, env, binary, "mod", "download", "-json", id)
			if err != nil {
				return nil, err
			}
			if err := json.Unmarshal(data, &capture.Download); err != nil || capture.Download.Error != "" ||
				capture.Download.Path != sourceModule || capture.Download.Version != sourceVersion ||
				capture.Download.Sum == "" || capture.Download.GoModSum == "" {
				return nil, fmt.Errorf("foreign type source lacks exact authenticated Go download: %v", err)
			}
			downloadedRoot, err := filepath.EvalSymlinks(capture.Download.Dir)
			if err != nil || downloadedRoot != root {
				return nil, fmt.Errorf("foreign type source differs from actual exact download root")
			}
			captures[id] = capture
		} else if capture.Root != root {
			return nil, fmt.Errorf("foreign type source reused exact identity at another root")
		}
		if err := budget.check(root, actual.Dir); err != nil {
			return nil, err
		}
		if err := captureDiscoveryTestSourceDirectory(capture.Plan, root, actual.Dir); err != nil {
			return nil, err
		}
		if err := captureDiscoveryTestModuleGoMod(ctx, capture, directory, env); err != nil {
			return nil, err
		}
		actualMod, err := discoveryFeatureFileSHA256(metadata)
		downloadedMod, modErr := discoveryFeatureFileSHA256(capture.Download.GoMod)
		if err != nil || modErr != nil || actualMod != downloadedMod {
			return nil, fmt.Errorf("foreign type actual metadata differs from exact source download")
		}
		capture.Metadata[metadata], capture.Metadata[capture.Download.GoMod] = actualMod, downloadedMod
	}
	if !seen[input.Plan.PackagePath] {
		return nil, fmt.Errorf("instrumentation source-only graph omitted its actual original root")
	}
	sources := []gotoolprofile.TestModuleSource{}
	for _, capture := range captures {
		source, err := discoveryTestModuleSnapshot(capture)
		if err != nil {
			return nil, err
		}
		if err := gotoolprofile.VerifyTestModuleSource(ctx, source, capture.Root, capture.Download.Zip); err != nil {
			return nil, err
		}
		for metadata := range capture.Metadata {
			if err := gotoolprofile.VerifyTestModuleGoModMetadata(source, capture.Root, metadata, capture.Download.GoMod); err != nil {
				return nil, err
			}
		}
		sources = append(sources, source)
	}
	gotoolprofile.SortTestModuleSources(sources)
	// The same bounded actual binder is consumed again independently in the CLI.
	if _, err := gotoolprofile.BindInstrumentationTypeModuleSources(ctx, binary, directory, env, sources, gotoolprofile.RunBounded); err != nil {
		return nil, err
	}
	return sources, nil
}
