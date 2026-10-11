package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func discoveryCPPFilesNeedGeneratedMetadata(inputs *discoveryCPPInputs, files []string) bool {
	if inputs == nil {
		return false
	}
	for _, unit := range inputs.Units {
		if !containsTargetFeature(files, unit.File) {
			continue
		}
		for _, kind := range unit.DeferredIncludes {
			if kind == "generated_go_asm" {
				return true
			}
		}
	}
	return false
}

// Same-module Go dependencies need original pre-load hashes too, even if their
// directories contain no candidate assembly. Ask the actual same-profile Go
// driver for the dependency set; never guess selected files or invent exports.
func captureDiscoveryGeneratedGoSources(ctx context.Context, plan *discoveryOrdinarySelectionPlan, dir, sourceRoot string, env []string, tags, patterns []string) error {
	args := []string{"list", "-deps", "-compiled", "-e", "-json", "-mod=mod"}
	if len(tags) != 0 {
		args = append(args, "-tags="+strings.Join(tags, ","))
	}
	args = append(args, patterns...)
	data, _, err := runDiscoveryMachineCommand(ctx, dir, env, "go", args...)
	if err != nil {
		return err
	}
	canonicalRoot, err := filepath.EvalSymlinks(sourceRoot)
	if err != nil {
		return err
	}
	if plan.GeneratedGoSources == nil {
		plan.GeneratedGoSources = make(map[string]string)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	count := 0
	for {
		var pkg struct {
			CompiledGoFiles []string
			Dir             string
			Module          *struct{ Dir string }
		}
		if err := decoder.Decode(&pkg); err == io.EOF {
			break
		} else if err != nil {
			return fmt.Errorf("decode actual generated-header dependency selection: %w", err)
		}
		count++
		if count > 4096 || ctx.Err() != nil {
			return fmt.Errorf("generated-header dependency selection exceeds live bounded scope: %v", ctx.Err())
		}
		if pkg.Module == nil || pkg.Module.Dir == "" {
			continue
		}
		root, err := filepath.EvalSymlinks(pkg.Module.Dir)
		if err != nil {
			return err
		}
		if root != canonicalRoot {
			continue
		}
		for _, file := range pkg.CompiledGoFiles {
			if !filepath.IsAbs(file) {
				file = filepath.Join(pkg.Dir, file)
			}
			file, err = filepath.EvalSymlinks(file)
			if err != nil {
				return err
			}
			if err := discoveryCPPRegularSource(canonicalRoot, file); err != nil {
				return err
			}
			name, err := filepath.Rel(canonicalRoot, file)
			name = filepath.ToSlash(name)
			if err != nil || !ordinarySelectionLocalPath(name) || !strings.HasSuffix(name, ".go") || len(plan.GeneratedGoSources) >= 32768 {
				return fmt.Errorf("generated-header dependency has an unbound/oversized ordinary source role")
			}
			digest, err := discoveryFeatureFileSHA256(file)
			if err != nil {
				return err
			}
			if before := plan.GeneratedGoSources[name]; before != "" && before != digest {
				return fmt.Errorf("original imported Go bytes changed between generated-header scopes")
			}
			plan.GeneratedGoSources[name] = digest
		}
	}
	return nil
}

func verifyDiscoveryGeneratedGoSources(plan *discoveryOrdinarySelectionPlan, root, zipPath string) error {
	if plan == nil {
		return fmt.Errorf("missing generated-header original source proof")
	}
	return verifyDiscoveryOriginalSourceMap(plan, root, zipPath, plan.GeneratedGoSources)
}

// Shared original ZIP membership boundary; source roles remain separately
// recorded by their callers instead of impersonating generated header inputs.
func verifyDiscoveryOriginalSourceMap(plan *discoveryOrdinarySelectionPlan, root, zipPath string, sources map[string]string) error {
	if len(sources) == 0 {
		return nil
	}
	// Initial ordinary ZIP verification authenticates h1 and records all archive
	// bytes. Imported Go files cannot weaken that boundary to selected members:
	// even a comment-only archive change invalidates this original snapshot.
	before, err := discoveryFeatureFileSHA256(zipPath)
	if err != nil || !discoverySHA256Pattern.MatchString(plan.ZipSHA256) || before != plan.ZipSHA256 {
		return fmt.Errorf("generated-header original ZIP bytes changed after initial verification")
	}
	archive, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer archive.Close()
	entries := make(map[string]*zip.File)
	prefix := plan.Module + "@" + plan.Version + "/"
	for _, entry := range archive.File {
		if entry.FileInfo().IsDir() {
			continue // Legal module ZIP directory entries carry no source bytes.
		}
		name := strings.TrimPrefix(entry.Name, prefix)
		if !strings.HasPrefix(entry.Name, prefix) || !ordinarySelectionLocalPath(name) || !entry.Mode().IsRegular() || entries[name] != nil {
			return fmt.Errorf("generated-header original ZIP has an unsafe/duplicate source member")
		}
		entries[name] = entry
	}
	for file, wanted := range sources {
		entry := entries[file]
		if entry == nil || entry.UncompressedSize64 > 64<<20 {
			return fmt.Errorf("generated-header imported Go source is not an exact ZIP member")
		}
		reader, err := entry.Open()
		if err != nil {
			return err
		}
		data, readErr := io.ReadAll(io.LimitReader(reader, 64<<20+1))
		closeErr := reader.Close()
		actual, sourceErr := discoveryFeatureFileSHA256(filepath.Join(root, filepath.FromSlash(file)))
		if readErr != nil || closeErr != nil || sourceErr != nil || discoveryFeatureBytesSHA256(data) != wanted || actual != wanted {
			return fmt.Errorf("generated-header imported Go source differs from exact original ZIP/pre-load bytes")
		}
	}
	after, err := discoveryFeatureFileSHA256(zipPath)
	if err != nil || after != before {
		return fmt.Errorf("generated-header original ZIP changed while imported Go sources were verified")
	}
	return nil
}

func captureDiscoveryGeneratedHeaderQuery(ctx context.Context, plan *discoveryOrdinarySelectionPlan, download moduleDownloadInfo, profile discoveryFeatureProfile, tags []string, group discoveryPackageGroup, dir string, env []string, translator string, index int) (*gotoolprofile.MetadataProof, error) {
	if !filepath.IsAbs(translator) {
		return nil, fmt.Errorf("generated header requires an actual absolute metadata consumer executable (not N/A)")
	}
	module, err := ordinaryProfileDeclaredModule(plan)
	if err != nil {
		return nil, err
	}
	if err := captureDiscoveryGeneratedGoSources(ctx, plan, dir, download.Dir, env, tags, []string{group.Pattern}); err != nil {
		return nil, err
	}
	if err := verifyDiscoveryGeneratedGoSources(plan, download.Dir, download.Zip); err != nil {
		return nil, err
	}
	input := ordinaryProfileConsumerInput(plan, profile, module, download.Dir, group.AsmFiles, tags)
	input.GeneratedHeaders = nil // Producer query, never recursive consumption.
	data, err := gotoolprofile.MarshalConsumerInput(input)
	if err != nil {
		return nil, err
	}
	inputPath := filepath.Join(dir, fmt.Sprintf("generated-header-input-%04d.json", index))
	reportPath := filepath.Join(dir, fmt.Sprintf("generated-header-query-%04d.json", index))
	outputPath := filepath.Join(dir, fmt.Sprintf("generated-header-oracle-%04d", index))
	if err := os.WriteFile(inputPath, data, 0600); err != nil {
		return nil, err
	}
	parts := strings.Split(profile.Observed.Target, "/")
	args := []string{"-metadata-only", "-goos=" + parts[0], "-goarch=" + parts[1],
		"-module-path=" + module, "-patterns=" + group.Pattern, "-asm-files=" + strings.Join(group.AsmFiles, ","),
		"-feature-profile=" + inputPath, "-out=" + outputPath, "-report=" + reportPath}
	if len(tags) != 0 {
		args = append(args, "-tags="+strings.Join(tags, ","))
	}
	_, _, err = runDiscoveryMachineCommand(ctx, dir, env, translator, args...)
	if err != nil {
		return nil, err
	}
	reader, err := os.Open(reportPath)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	var proof gotoolprofile.MetadataProof
	decoder := json.NewDecoder(io.LimitReader(reader, 16<<20+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&proof); err != nil {
		return nil, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("metadata-only report contains trailing input")
	}
	if err := gotoolprofile.ValidateMetadata(input, &proof, tags); err != nil {
		return nil, err
	}
	if err := verifyDiscoveryOrdinaryDependencies(ctx, plan, download, proof.Dependencies, dir, env); err != nil {
		return nil, err
	}
	if err := verifyDiscoveryGeneratedGoSources(plan, download.Dir, download.Zip); err != nil {
		return nil, err
	}
	return &proof, nil
}
