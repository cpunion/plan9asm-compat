package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/build/constraint"
	"io"
	"path"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/mod/modfile"
)

// Planning queries observe real compiler inputs but are never executed LLVM
// scopes. Complete original Go bytes are shared once across these queries.
type discoveryCPPHeaderPlanning struct {
	Protocol        string                                 `json:"protocol"`
	Rules           *gotoolprofile.NativeHeaderSourceRules `json:"rules"`
	Sources         map[string]string                      `json:"sources"`
	ImportedSources map[string]string                      `json:"imported_sources,omitempty"`
	Queries         []discoveryCPPHeaderPlanningQuery      `json:"queries"`
}

type discoveryCPPHeaderPlanningQuery struct {
	Assembly         string                           `json:"assembly"`
	Profile          discoveryFeatureProfileReference `json:"profile"`
	BuildTags        []string                         `json:"build_tags,omitempty"`
	Metadata         *gotoolprofile.MetadataProof     `json:"metadata"`
	ImportedGoSHA256 map[string]string                `json:"imported_go_sha256,omitempty"`
}

const discoveryCPPHeaderPlanningProtocol = "original_native_header_planning_query_v1"

type discoveryHeaderPlanningUnsupported struct{ reason string }

func (err *discoveryHeaderPlanningUnsupported) Error() string { return err.reason }

func validateDiscoveryPlanningSources(role *discoveryCPPHeaderPlanning) error {
	if role == nil || len(role.Sources) == 0 || len(role.Sources)+len(role.ImportedSources) > 4096 {
		return fmt.Errorf("native planning source collection is absent or unbounded")
	}
	total := 0
	for _, sources := range []map[string]string{role.Sources, role.ImportedSources} {
		for name, text := range sources {
			if !ordinarySelectionLocalPath(name) || !strings.HasSuffix(name, ".go") ||
				strings.HasSuffix(name, "_test.go") || len(text) > 2<<20 || len(text) > 16<<20-total || strings.ContainsRune(text, '\x00') {
				return fmt.Errorf("native planning source role or total byte bound is unclosed")
			}
			total += len(text)
		}
	}
	return nil
}

func discoveryHeaderPlanningKey(request discoveryFeatureProfileRequest, assembly string, tags []string) string {
	data, _ := json.Marshal(request) // All fields are bounded strings/maps/bools.
	return assembly + "\x00" + string(data) + "\x00" + strings.Join(tags, "\x00")
}

func discoveryPlanningHeader(plan *discoveryOrdinarySelectionPlan, request discoveryFeatureProfileRequest, assembly string, tags []string) (*gotoolprofile.GeneratedHeaderProof, error) {
	if plan.headerPlanningCapture != nil {
		return plan.headerPlanningCapture(request, assembly, tags)
	}
	role := plan.HeaderPlanning
	if role == nil {
		return nil, fmt.Errorf("actual native planning header query is absent")
	}
	if role.Protocol != discoveryCPPHeaderPlanningProtocol || len(role.Queries) == 0 || len(role.Queries) > 4096 || len(role.Sources) == 0 || len(role.Sources) > 32768 {
		return nil, fmt.Errorf("actual native planning header role is missing, unbounded or downgraded")
	}
	if err := validateDiscoveryPlanningSources(role); err != nil {
		return nil, err
	}
	if err := gotoolprofile.ValidateNativeHeaderSourceRules(role.Rules, plan.GoVersion); err != nil {
		return nil, err
	}
	key := discoveryHeaderPlanningKey(request, assembly, tags)
	var found *discoveryCPPHeaderPlanningQuery
	for index := range role.Queries {
		query := &role.Queries[index]
		if discoveryHeaderPlanningKey(query.Profile.Request, query.Assembly, query.BuildTags) == key {
			if found != nil {
				return nil, fmt.Errorf("duplicate native header planning query")
			}
			found = query
		}
	}
	if found == nil {
		// No query is no planning evidence. Retain every legal CPU proposal
		// and require each final package/tag scope's independent source or
		// object proof. Existing malformed receipts still fail below; an
		// omitted receipt can expand, never shrink, the final denominator.
		return nil, &discoveryHeaderPlanningUnsupported{reason: "native header planning query omits its exact request/source/tag scope"}
	}
	profiles, err := resolveDiscoveryFeatureProfiles(plan.headerPlanningInventory, []discoveryFeatureProfileReference{found.Profile})
	if err != nil {
		return nil, err
	}
	profile := profiles[0]
	if profile.Observed.GoVersion != plan.GoVersion || profile.Request.Target != profile.Observed.Target ||
		profile.Request.Baseline != (len(profile.Request.Overrides) == 0) || !equalDiscoveryStrings(tags, uniqueSortedDiscoveryStrings(tags)) {
		return nil, fmt.Errorf("planning query differs from its actual source/SDK/target/tag scope")
	}
	for name, value := range request.Overrides {
		if profile.Observed.Environment[name] != value {
			return nil, fmt.Errorf("planning query did not observe its requested environment")
		}
	}
	module, err := ordinaryProfileDeclaredModule(plan)
	if err != nil {
		return nil, err
	}
	queryPlan, err := discoveryHeaderQuerySourcePlan(plan, profile, assembly, tags)
	if err != nil {
		return nil, err
	}
	queryPlan.GeneratedGoSources, err = replayDiscoveryPlanningImports(role, found, module)
	if err != nil {
		return nil, err
	}
	input := ordinaryProfileConsumerInput(queryPlan, profile, module, "", []string{assembly}, tags)
	input.GeneratedHeaders = nil
	if err := gotoolprofile.ValidateMetadata(input, found.Metadata, tags); err != nil {
		return nil, err
	}
	if len(found.Metadata.Packages) != 1 || len(found.Metadata.Headers) != 1 {
		return nil, fmt.Errorf("planning query expanded beyond one original selected package")
	}
	header := found.Metadata.Headers[0]
	language, err := discoveryHeaderPlanningLanguage(plan)
	if err != nil || header.LanguageVersion != language {
		return nil, fmt.Errorf("planning query language differs from original module metadata: %v", err)
	}
	wantedPackage := module
	if directory := path.Dir(assembly); directory != "." {
		wantedPackage += "/" + directory
	}
	if header.PackagePath != wantedPackage {
		return nil, fmt.Errorf("planning header has a different original package namespace")
	}
	sources := make(map[string]string)
	for name, digest := range header.CompiledGoSHA256 {
		text, present := role.Sources[name]
		if !present || input.Sources[name] != digest || discoveryFeatureBytesSHA256([]byte(text)) != digest || path.Dir(name) != path.Dir(assembly) {
			return nil, fmt.Errorf("planning header lacks its complete original selected compiler Go bytes")
		}
		sources[name] = text
	}
	definitions, err := gotoolprofile.ReplayNativeGeneratedHeaderWithImportMap(header.PackagePath, header.Target,
		header.LanguageVersion, sources, header.ImportMap)
	if err != nil {
		return nil, fmt.Errorf("independent original native header source replay: %w", err)
	}
	if !reflect.DeepEqual(definitions, header.Definitions) {
		return nil, fmt.Errorf("actual planning header differs from independent original native source replay: %v", err)
	}
	if plan.headerPlanningUsed != nil {
		plan.headerPlanningUsed[key] = true
	}
	return &header, nil
}

func discoveryHeaderPlanningLanguage(plan *discoveryOrdinarySelectionPlan) (string, error) {
	var contents string
	if plan.ProxyGoMod != nil {
		if err := validateDiscoveryProxyGoMod(plan); err != nil {
			return "", err
		}
		contents = plan.ProxyGoMod.Contents
	} else {
		for _, source := range plan.Sources {
			if source.File != "go.mod" {
				continue
			}
			if contents != "" || discoveryFeatureBytesSHA256([]byte(source.Header)) != source.SHA256 {
				return "", fmt.Errorf("planning module metadata is duplicate or not complete original bytes")
			}
			contents = source.Header
		}
	}
	if contents == "" {
		return "", fmt.Errorf("planning query has no exact original module language source")
	}
	module, err := modfile.Parse("go.mod", []byte(contents), nil)
	if err != nil || module.Module == nil {
		return "", fmt.Errorf("planning original module language parse: %v", err)
	}
	if module.Go == nil {
		return "go1.16", nil // Same actual cmd/go default used by the native query.
	}
	parts := strings.Split(module.Go.Version, ".")
	if len(parts) == 1 && parts[0] == "1" {
		return "go1", nil
	}
	if len(parts) < 2 {
		return "", fmt.Errorf("planning module language is not independently canonical")
	}
	return "go" + strings.Join(parts[:2], "."), nil
}

// A planning profile need not be one of the final executed profiles. Replay
// its complete package selection directly, without recursively requesting the
// final CPP profile denominator or borrowing another profile's decisions.
func discoveryHeaderQuerySourcePlan(plan *discoveryOrdinarySelectionPlan, profile discoveryFeatureProfile, assembly string, tags []string) (*discoveryOrdinarySelectionPlan, error) {
	if plan == nil || profile.Observed == nil || !containsTargetFeature(plan.TestedAsmFiles, assembly) ||
		len(tags) > 16 || !equalDiscoveryStrings(tags, uniqueSortedDiscoveryStrings(tags)) {
		return nil, fmt.Errorf("native planning query lacks its canonical package/tag scope")
	}
	for _, tag := range tags {
		expression, err := constraint.Parse("//go:build " + tag)
		name, single := expression.(*constraint.TagExpr)
		if err != nil || !single || name.Tag != tag || gotoolprofile.ReservedTag(tag) {
			return nil, fmt.Errorf("native planning custom tag cannot impersonate a source expression or tool profile: %q", tag)
		}
	}
	copy := *plan
	copy.Targets = []string{profile.Observed.Target}
	copy.ToolTags = append([]string(nil), profile.Observed.ToolTags...)
	decisions, selected, err := replayOrdinarySelection(&copy, plan.TestedAsmFiles, profile.Observed)
	if err != nil {
		return nil, err
	}
	// A Go partner may require a custom tag combination that no assembly
	// file proposed. Bind this query's actual scope before closing siblings;
	// do not borrow a different tag profile or alter final execution scopes.
	possible := false
	for key := range selected {
		if key.File == assembly {
			possible = true
		}
	}
	if !possible {
		return nil, fmt.Errorf("native planning query assembly has no original ordinary package role")
	}
	sources, _, err := ordinarySelectionBytes(&copy)
	if err != nil {
		return nil, err
	}
	ctx, err := discoveryContextForFeatureProfile(profile.Observed)
	if err != nil {
		return nil, err
	}
	ctx.BuildTags = append([]string(nil), tags...)
	ctx.OpenFile = func(file string) (io.ReadCloser, error) {
		data, found := sources[filepath.ToSlash(file)]
		if !found {
			return nil, fmt.Errorf("native planning query lacks original selection bytes: %s", file)
		}
		return io.NopCloser(bytes.NewReader(data)), nil
	}
	active, err := ctx.MatchFile(filepath.FromSlash(path.Dir(assembly)), path.Base(assembly))
	if err != nil || !active {
		return nil, fmt.Errorf("native planning query assembly is not selected by its exact tags: %s: %v", assembly, err)
	}
	key := nativeLayoutKey(assembly, profile.Observed.Target, tags)
	if !selected[key] {
		selected[key] = true
		decisions = append(decisions, ordinarySelectionDecision{
			AsmFiles: []string{assembly}, Targets: []string{profile.Observed.Target},
			BuildTags: append([]string(nil), tags...), Kind: nativeLayoutSelected,
			Diagnostic: "Go MatchFile selects this original assembly for the exact package/custom-tag metadata query; no LLVM execution scope is granted",
		})
	}
	decisions, err = closeOrdinaryPackageTagScopes(&copy, plan.TestedAsmFiles, decisions, selected, profile.Observed)
	if err != nil {
		return nil, err
	}
	copy.ProfileDecisions = nil
	for _, decision := range decisions {
		copy.ProfileDecisions = append(copy.ProfileDecisions, ordinaryProfileDecision{profile.ID, decision})
	}
	return &copy, nil
}

func validateDiscoveryPlanningConsumption(plan *discoveryOrdinarySelectionPlan) error {
	if plan.HeaderPlanning == nil {
		return nil
	}
	role := plan.HeaderPlanning
	usedSources := make(map[string]bool)
	usedImports := make(map[string]bool)
	seen := make(map[string]bool)
	for _, query := range role.Queries {
		key := discoveryHeaderPlanningKey(query.Profile.Request, query.Assembly, query.BuildTags)
		if seen[key] || !plan.headerPlanningUsed[key] || query.Metadata == nil || len(query.Metadata.Headers) != 1 {
			return fmt.Errorf("duplicate, unconsumed or incomplete native header planning query")
		}
		seen[key] = true
		for name := range query.Metadata.Headers[0].CompiledGoSHA256 {
			usedSources[name] = true
		}
		for name := range query.ImportedGoSHA256 {
			usedImports[name] = true
		}
	}
	if len(seen) == 0 || len(usedSources) != len(role.Sources) || len(usedImports) != len(role.ImportedSources) {
		return fmt.Errorf("native header planning has an empty query or unconsumed original source")
	}
	return nil
}
