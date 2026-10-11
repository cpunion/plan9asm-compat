package main

import (
	"bytes"
	"fmt"
	"go/build"
	"go/parser"
	"go/token"
	"io"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

type discoveryProfileScope struct {
	File, Target, ProfileID, Tags string
}

type ordinaryProfileDecision struct {
	ProfileID string `json:"profile_id"`
	ordinarySelectionDecision
}

const ordinaryPackageTagScopeLimit = 4096

type ordinaryPackageTagScope struct {
	Dir, Tags string
}

func addOrdinaryPackageTagScope(scopes map[ordinaryPackageTagScope]bool, scope ordinaryPackageTagScope) error {
	if !scopes[scope] && len(scopes) >= ordinaryPackageTagScopeLimit {
		return fmt.Errorf("ordinary package/custom-tag scopes exceed explicit %d-scope bound (not N/A)", ordinaryPackageTagScopeLimit)
	}
	scopes[scope] = true
	return nil
}

func replayOrdinarySelectionForProfiles(plan *discoveryOrdinarySelectionPlan, asmFiles []string, profiles []discoveryFeatureProfile) ([]ordinaryProfileDecision, map[discoveryProfileScope]bool, error) {
	if err := validateDiscoveryFeatureProfiles(plan, asmFiles, profiles); err != nil {
		return nil, nil, err
	}
	var decisions []ordinaryProfileDecision
	eligible := make(map[discoveryProfileScope]bool)
	for _, profile := range profiles {
		copy := *plan
		copy.Targets = []string{profile.Observed.Target}
		copy.ToolTags = append([]string(nil), profile.Observed.ToolTags...)
		replayed, keys, err := replayOrdinarySelection(&copy, asmFiles, profile.Observed)
		if err != nil {
			return nil, nil, err
		}
		replayed, err = closeOrdinaryPackageTagScopesWithGoPartners(&copy, asmFiles, replayed, keys, profile.Observed, true)
		if err != nil {
			return nil, nil, err
		}
		for _, decision := range replayed {
			decisions = append(decisions, ordinaryProfileDecision{profile.ID, decision})
		}
		for key := range keys {
			eligible[discoveryProfileScope{key.File, key.Target, profile.ID, key.Tags}] = true
		}
	}
	return decisions, eligible, nil
}

// A tag configuration selects a whole package, not just the file whose
// constraint proposed those tags. Shared assembly must therefore be checked
// again with the declarations selected by every package-local configuration.
// Do not spread one package's custom tags to unrelated packages.
func closeOrdinaryPackageTagScopes(plan *discoveryOrdinarySelectionPlan, asmFiles []string, decisions []ordinarySelectionDecision, eligible map[nativeLayoutPlanKey]bool, actual *discoveryTargetFeatures) ([]ordinarySelectionDecision, error) {
	// A private metadata query closes only its explicit package/tag scope;
	// it must not register unrelated Go-only partner scopes as query inputs.
	return closeOrdinaryPackageTagScopesWithGoPartners(plan, asmFiles, decisions, eligible, actual, false)
}

func closeOrdinaryPackageTagScopesWithGoPartners(plan *discoveryOrdinarySelectionPlan, asmFiles []string, decisions []ordinarySelectionDecision, eligible map[nativeLayoutPlanKey]bool, actual *discoveryTargetFeatures, includeGoPartners bool) ([]ordinarySelectionDecision, error) {
	scopeSet := make(map[ordinaryPackageTagScope]bool)
	packageDirs := make(map[string]bool)
	for key := range eligible {
		packageDirs[path.Dir(key.File)] = true
		if err := addOrdinaryPackageTagScope(scopeSet, ordinaryPackageTagScope{Dir: path.Dir(key.File), Tags: key.Tags}); err != nil {
			return nil, err
		}
	}
	sources, _, err := ordinarySelectionBytes(plan)
	if err != nil {
		return nil, err
	}
	ctx, err := discoveryContextForFeatureProfile(actual)
	if err != nil {
		return nil, err
	}
	ctx.OpenFile = func(file string) (io.ReadCloser, error) {
		data, found := sources[filepath.ToSlash(file)]
		if !found {
			return nil, fmt.Errorf("uncaptured package/tag selection source %s", file)
		}
		return io.NopCloser(bytes.NewReader(data)), nil
	}
	if includeGoPartners {
		if err := addOrdinaryGoPartnerTagScopes(ctx, sources, asmFiles, packageDirs, scopeSet); err != nil {
			return nil, err
		}
	}
	var scopes []ordinaryPackageTagScope
	for scope := range scopeSet {
		scopes = append(scopes, scope)
	}
	sort.Slice(scopes, func(i, j int) bool {
		if scopes[i].Dir != scopes[j].Dir {
			return scopes[i].Dir < scopes[j].Dir
		}
		return scopes[i].Tags < scopes[j].Tags
	})
	for _, scope := range scopes {
		ctx.BuildTags = nil
		if scope.Tags != "" {
			ctx.BuildTags = strings.Split(scope.Tags, "\x00")
		}
		for _, file := range asmFiles {
			if path.Dir(file) != scope.Dir {
				continue
			}
			key := nativeLayoutKey(file, actual.Target, ctx.BuildTags)
			if eligible[key] {
				continue
			}
			selected, err := ctx.MatchFile(filepath.FromSlash(scope.Dir), path.Base(file))
			if err != nil {
				return nil, fmt.Errorf("replay package/tag assembly selection for %s: %w", file, err)
			}
			if !selected {
				continue
			}
			eligible[key] = true
			decisions = append(decisions, ordinarySelectionDecision{
				AsmFiles: []string{file}, Targets: []string{actual.Target},
				BuildTags:  append([]string(nil), ctx.BuildTags...),
				Kind:       nativeLayoutSelected,
				Diagnostic: "Go MatchFile selects this shared assembly in a required package/custom-tag configuration; compiler/assembler acceptance is checked separately",
			})
		}
	}
	return compactOrdinarySelectionDecisions(decisions), nil
}

func addOrdinaryGoPartnerTagScopes(ctx build.Context, sources map[string][]byte, asmFiles []string, packageDirs map[string]bool, scopeSet map[ordinaryPackageTagScope]bool) error {
	// Feature planning considers each Go partner separately. Preserve its
	// minimal configuration here too: a shared untagged declaration must not
	// erase a tag that only changes another selected Go file. This is not a
	// power set of unrelated package tags and does not invent CPU profiles.
	goFiles := make(map[string][]string)
	malformed := make(map[string]bool)
	tagsByFile := make(map[string][]string)
	for file, data := range sources {
		if !packageDirs[path.Dir(file)] || strings.HasPrefix(path.Base(file), ".") ||
			strings.HasPrefix(path.Base(file), "_") || strings.HasSuffix(file, "_test.go") {
			continue
		}
		if strings.HasSuffix(file, ".go") {
			if _, err := parser.ParseFile(token.NewFileSet(), file, data, parser.PackageClauseOnly); err != nil {
				malformed[file] = true
			}
			goFiles[path.Dir(file)] = append(goFiles[path.Dir(file)], path.Base(file))
		} else if !containsTargetFeature(asmFiles, file) {
			continue
		}
		expression, err := discoveryFileBuildExpression(filepath.FromSlash(file), ctx.OpenFile)
		if err != nil {
			return err
		}
		tags := make(map[string]bool)
		if expression != nil {
			collectDiscoveryConstraintTags(expression, tags)
		}
		tagsByFile[filepath.FromSlash(file)] = sortedDiscoverySet(tags)
	}
	for _, assembly := range asmFiles {
		dir := path.Dir(assembly)
		partners := goFiles[dir]
		sort.Strings(partners)
		for _, partner := range partners {
			allTags := append(append([]string(nil), tagsByFile[filepath.FromSlash(assembly)]...), tagsByFile[filepath.Join(filepath.FromSlash(dir), partner)]...)
			custom := discoveryCustomTagsWithoutFeatures(allTags, []build.Context{ctx})
			matchGo := discoveryGoFileMatches
			if malformed[path.Join(dir, partner)] {
				// A syntax rejection cannot erase the tag that exposes it.
				// Match only the original filename/build constraints here;
				// this does not establish an importable Go or cgo partner.
				// The already eligible package still requires actual Go
				// rejection or full object evidence for this added scope.
				matchGo = func(ctx build.Context, dir, file string) (bool, error) {
					return ctx.MatchFile(dir, file)
				}
			}
			tags, selected, err := findDiscoveryBuildTagsWithGoMatcher(ctx, filepath.FromSlash(dir), path.Base(assembly), []string{partner}, custom, tagsByFile, matchGo)
			if err != nil {
				return err
			}
			if selected {
				if err := addOrdinaryPackageTagScope(scopeSet, ordinaryPackageTagScope{Dir: dir, Tags: strings.Join(tags, "\x00")}); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
