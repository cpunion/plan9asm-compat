package main

import (
	"fmt"
	"io"
	"path"
	"path/filepath"
	"strings"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

// This cost-only preflight may retain every CPU proposal. It cannot publish a
// planning query, select final compiler inputs or grant header/object credit.
func preflightDiscoveryHeaderQuery(plan *discoveryOrdinarySelectionPlan, profile discoveryFeatureProfile,
	download moduleDownloadInfo, assembly string, tags []string) error {
	if plan == nil || profile.Observed == nil || profile.Request.Target != profile.Observed.Target {
		return fmt.Errorf("planning preflight lacks its source/profile scope")
	}
	selection, err := discoveryContextForFeatureProfile(profile.Observed)
	if err != nil {
		return err
	}
	selection.BuildTags = append([]string(nil), tags...)
	headers := make(map[string]ordinarySelectionSource)
	for _, source := range plan.Sources {
		if _, duplicate := headers[source.File]; duplicate {
			return fmt.Errorf("planning preflight source inventory is duplicated")
		}
		headers[source.File] = source
	}
	selection.OpenFile = func(name string) (io.ReadCloser, error) {
		source, found := headers[filepath.ToSlash(name)]
		if !found {
			return nil, fmt.Errorf("planning preflight lacks the original selection header")
		}
		return io.NopCloser(strings.NewReader(source.Header)), nil
	}
	directory := path.Dir(assembly)
	sources, hashes := make(map[string]string), make(map[string]string)
	for _, source := range plan.Sources {
		if path.Dir(source.File) != directory || !strings.HasSuffix(source.File, ".go") ||
			strings.HasSuffix(source.File, "_test.go") || strings.HasPrefix(path.Base(source.File), ".") ||
			strings.HasPrefix(path.Base(source.File), "_") {
			continue
		}
		selected, err := selection.MatchFile(directory, path.Base(source.File))
		if err != nil {
			return err
		}
		if !selected {
			continue
		}
		name := filepath.Join(download.Dir, filepath.FromSlash(source.File))
		if err := discoveryCPPRegularSource(download.Dir, name); err != nil {
			return err
		}
		data, err := readDiscoveryHeaderPlanningSource(name)
		if err != nil || discoveryFeatureBytesSHA256(data) != source.SHA256 {
			return fmt.Errorf("planning preflight differs from complete original source bytes: %v", err)
		}
		fullSelection := selection
		fullSelection.OpenFile = func(string) (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(string(data))), nil
		}
		full, err := fullSelection.MatchFile(directory, path.Base(source.File))
		if err != nil || !full {
			return fmt.Errorf("planning preflight source and selection header disagree: %v", err)
		}
		sources[source.File], hashes[source.File] = string(data), source.SHA256
	}
	if err := validateDiscoveryPlanningSources(&discoveryCPPHeaderPlanning{Sources: sources}); err != nil {
		return err
	}
	if err := verifyDiscoveryOriginalSourceMap(plan, download.Dir, download.Zip, hashes); err != nil {
		return err
	}
	module, err := ordinaryProfileDeclaredModule(plan)
	if err != nil {
		return err
	}
	if directory != "." {
		module += "/" + directory
	}
	language, err := discoveryHeaderPlanningLanguage(plan)
	if err != nil {
		return err
	}
	return gotoolprofile.PreflightNativeGeneratedHeaderSource(module, profile.Request.Target, language, sources)
}
