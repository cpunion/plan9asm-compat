package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/build"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	nativeLayoutSelected          = "selected"
	nativeLayoutBuildConstraints  = "go_build_constraints"
	nativeLayoutIgnoredDirectory  = "go_ignored_directory"
	nativeLayoutNestedModule      = "nested_module"
	nativeLayoutGoAssemblerTarget = "go_assembler_rejected_target"
)

// This proof is collected while reading the downloaded source, before any
// exception filter or package check. Execution configurations are separate:
// an empty post-filter allowlist cannot prove that the remainder was empty.
type discoveryNativeLayoutPlan struct {
	GoVersion           string                        `json:"go_version"`
	Targets             []string                      `json:"targets"`
	ReleaseTags         []string                      `json:"release_tags"`
	ToolTags            []string                      `json:"tool_tags"`
	Selections          []nativeLayoutSourceSelection `json:"source_selections"`
	SourceInventory     []nativeLayoutSourceInput     `json:"source_inventory"`
	BuildConfigurations []discoveryBuildConfiguration `json:"build_configurations"`
}

type nativeLayoutSourceInput struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Header string `json:"constraint_header,omitempty"`
}

type nativeLayoutSourceSelection struct {
	Assembly       nativeLayoutSourceInput         `json:"assembly"`
	GoFiles        []nativeLayoutSourceInput       `json:"go_files,omitempty"`
	ExcludedKind   string                          `json:"excluded_kind,omitempty"`
	ExcludedReason string                          `json:"excluded_reason,omitempty"`
	NestedModule   *nativeLayoutSourceInput        `json:"nested_module,omitempty"`
	Decisions      []nativeLayoutSelectionDecision `json:"decisions,omitempty"`
}

type nativeLayoutSelectionDecision struct {
	Target    string   `json:"target"`
	BuildTags []string `json:"build_tags,omitempty"`
	Kind      string   `json:"kind"`
	Reason    string   `json:"reason,omitempty"`
}

func recordNativeLayoutSourceInput(plan *discoveryNativeLayoutPlan, input nativeLayoutSourceInput) {
	for _, existing := range plan.SourceInventory {
		if existing.File == input.File {
			return
		}
	}
	plan.SourceInventory = append(plan.SourceInventory, input)
}

func readNativeLayoutSourceInput(moduleDir, file string) (nativeLayoutSourceInput, error) {
	data, err := os.ReadFile(filepath.Join(moduleDir, filepath.FromSlash(file)))
	if err != nil {
		return nativeLayoutSourceInput{}, fmt.Errorf("read native-layout selection input %s: %w", file, err)
	}
	return nativeLayoutSourceInputFromBytes(file, data)
}

func nativeLayoutSourceInputFromBytes(file string, data []byte) (nativeLayoutSourceInput, error) {
	digest := sha256.Sum256(data)
	input := nativeLayoutSourceInput{File: file, SHA256: hex.EncodeToString(digest[:])}
	if strings.HasSuffix(file, ".go") {
		header, err := discoveryGoSelectionHeader(file, data)
		if err != nil {
			return input, err
		}
		input.Header = header
	} else if strings.HasSuffix(file, ".s") {
		// Preserve the original leading comments and blank-line placement, not
		// just extracted expressions: Go's legacy +build rules depend on both.
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Buffer(make([]byte, 64<<10), 4<<20)
		inBlock := false
		firstLine := true
		var header strings.Builder
		for scanner.Scan() {
			line := scanner.Text()
			selectionLine := line
			if firstLine {
				selectionLine = strings.TrimPrefix(selectionLine, "\ufeff")
				firstLine = false
			}
			trimmed := strings.TrimSpace(selectionLine)
			if !inBlock && trimmed != "" && !strings.HasPrefix(trimmed, "//") && !strings.HasPrefix(trimmed, "/*") {
				break
			}
			header.WriteString(line + "\n")
			if strings.HasPrefix(trimmed, "/*") {
				inBlock = true
			}
			if inBlock && strings.Contains(trimmed, "*/") {
				inBlock = false
			}
		}
		if err := scanner.Err(); err != nil {
			return input, err
		}
		input.Header = header.String()
	}
	return input, nil
}

func nativeLayoutNestedModuleInput(moduleDir, dir string) (*nativeLayoutSourceInput, error) {
	for dir != "." && dir != "" {
		file := path.Join(dir, "go.mod")
		input, err := readNativeLayoutSourceInput(moduleDir, file)
		if err == nil {
			return &input, nil
		}
		if !os.IsNotExist(err) {
			return nil, err
		}
		dir = path.Dir(dir)
	}
	return nil, fmt.Errorf("nested module has no go.mod evidence")
}

type nativeLayoutPlanKey struct {
	File   string
	Target string
	Tags   string
}

func nativeLayoutKey(file, target string, tags []string) nativeLayoutPlanKey {
	return nativeLayoutPlanKey{file, target, strings.Join(tags, "\x00")}
}

func nativeLayoutConfigurationKeys(configs []discoveryBuildConfiguration, files, targets map[string]bool) (map[nativeLayoutPlanKey]bool, error) {
	keys := make(map[nativeLayoutPlanKey]bool)
	for _, config := range configs {
		if len(config.AsmFiles) == 0 || len(config.Targets) == 0 ||
			!equalDiscoveryStrings(config.BuildTags, uniqueSortedDiscoveryStrings(config.BuildTags)) {
			return nil, fmt.Errorf("invalid native-layout build configuration")
		}
		for _, file := range config.AsmFiles {
			if !files[file] {
				return nil, fmt.Errorf("native-layout configuration has uninventoried file %s", file)
			}
			for _, target := range config.Targets {
				key := nativeLayoutKey(file, target, config.BuildTags)
				if !targets[target] || keys[key] {
					return nil, fmt.Errorf("duplicate or out-of-matrix native-layout configuration %v", key)
				}
				keys[key] = true
			}
		}
	}
	return keys, nil
}

func validNativeLayoutInput(input nativeLayoutSourceInput) bool {
	return filepath.IsLocal(input.File) && filepath.ToSlash(input.File) == input.File &&
		path.Clean(input.File) == input.File && discoverySHA256Pattern.MatchString(input.SHA256)
}

// Replay filename/build-constraint selection from independently captured
// source headers. OpenFile is virtual: verification neither downloads source
// nor reads the disposable module cache that produced the report.
func nativeLayoutSelectionMatches(plan *discoveryNativeLayoutPlan, selection nativeLayoutSourceSelection) (map[string][]string, error) {
	inputs := append([]nativeLayoutSourceInput{selection.Assembly}, selection.GoFiles...)
	contents := make(map[string]string, len(inputs))
	tagsByFile := make(map[string][]string, len(inputs))
	var goFiles, allTags []string
	for index, input := range inputs {
		if !validNativeLayoutInput(input) || path.Dir(input.File) != path.Dir(selection.Assembly.File) {
			return nil, fmt.Errorf("invalid native-layout source input %s", input.File)
		}
		if _, duplicate := contents[input.File]; duplicate {
			return nil, fmt.Errorf("duplicate native-layout source input %s", input.File)
		}
		contents[input.File] = input.Header
		if index != 0 {
			name := path.Base(input.File)
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") ||
				strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
				return nil, fmt.Errorf("invalid native-layout Go selection input %s", input.File)
			}
			if _, err := parser.ParseFile(token.NewFileSet(), name, input.Header, parser.PackageClauseOnly); err != nil {
				return nil, fmt.Errorf("invalid native-layout Go constraint header: %w", err)
			}
			goFiles = append(goFiles, name)
		}
		scanner := bufio.NewScanner(strings.NewReader(input.Header))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if !strings.HasPrefix(line, "//go:build ") && !strings.HasPrefix(line, "// +build ") {
				continue
			}
			expr, err := constraint.Parse(line)
			if err != nil {
				return nil, err
			}
			set := make(map[string]bool)
			collectDiscoveryConstraintTags(expr, set)
			tagsByFile[filepath.FromSlash(input.File)] = append(tagsByFile[filepath.FromSlash(input.File)], sortedDiscoverySet(set)...)
		}
		allTags = append(allTags, tagsByFile[filepath.FromSlash(input.File)]...)
	}
	contexts := make([]build.Context, 0, len(plan.Targets))
	for _, target := range plan.Targets {
		goos, goarch, _ := strings.Cut(target, "/")
		ctx := build.Default
		ctx.GOOS, ctx.GOARCH, ctx.Compiler, ctx.CgoEnabled = goos, goarch, "gc", false
		ctx.ReleaseTags, ctx.ToolTags = plan.ReleaseTags, plan.ToolTags
		ctx.OpenFile = func(file string) (io.ReadCloser, error) {
			data, exists := contents[filepath.ToSlash(file)]
			if !exists {
				return nil, fmt.Errorf("uncaptured native-layout selection input %s", file)
			}
			return io.NopCloser(strings.NewReader(data)), nil
		}
		contexts = append(contexts, ctx)
	}
	customTags := uniqueDiscoveryCustomTags(allTags, contexts)
	matches := make(map[string][]string)
	for index, ctx := range contexts {
		tags, ok, err := findDiscoveryBuildTags(ctx, filepath.FromSlash(path.Dir(selection.Assembly.File)),
			path.Base(selection.Assembly.File), goFiles, customTags, tagsByFile)
		if err != nil {
			return nil, err
		}
		if ok {
			matches[plan.Targets[index]] = tags
		}
	}
	return matches, nil
}

func validateNativeLayoutPlan(result discoveryCorpusResult) error {
	plan := result.NativeLayoutPlan
	if plan == nil || len(plan.Targets) == 0 || len(plan.ReleaseTags) == 0 || len(plan.Selections) == 0 {
		return fmt.Errorf("native-layout result lacks pre-filter source-selection plan")
	}
	minor, _, _ := strings.Cut(strings.TrimPrefix(plan.GoVersion, "go1."), ".")
	minorVersion, err := strconv.Atoi(minor)
	if !strings.HasPrefix(plan.GoVersion, "go1.") || err != nil || minorVersion < 1 || minorVersion > 100 {
		return fmt.Errorf("native-layout plan has invalid Go selection version")
	}
	var releaseTags []string
	for version := 1; version <= minorVersion; version++ {
		releaseTags = append(releaseTags, fmt.Sprintf("go1.%d", version))
	}
	if !equalDiscoveryStrings(plan.ReleaseTags, releaseTags) {
		return fmt.Errorf("native-layout plan release constraints differ from Go selection version")
	}
	files, targets := make(map[string]bool), make(map[string]bool)
	for _, file := range result.DiscoveredAsmFiles {
		if files[file] {
			return fmt.Errorf("duplicate native-layout discovered file %s", file)
		}
		files[file] = true
	}
	for _, target := range plan.Targets {
		if err := validateTarget(target); err != nil || targets[target] {
			return fmt.Errorf("invalid or duplicate native-layout plan target %s", target)
		}
		targets[target] = true
	}
	selected := make(map[nativeLayoutPlanKey]bool)
	preSourceNA := make(map[nativeLayoutPlanKey]string)
	inputs := make(map[string]nativeLayoutSourceInput)
	goInputsByDir := make(map[string]map[string]nativeLayoutSourceInput)
	for _, input := range plan.SourceInventory {
		if !validNativeLayoutInput(input) {
			return fmt.Errorf("invalid native-layout source inventory input")
		}
		if _, duplicate := inputs[input.File]; duplicate {
			return fmt.Errorf("duplicate native-layout source inventory input %s", input.File)
		}
		inputs[input.File] = input
		if strings.HasSuffix(input.File, ".go") {
			if _, err := parser.ParseFile(token.NewFileSet(), input.File, input.Header, parser.PackageClauseOnly); err != nil {
				return fmt.Errorf("native-layout source inventory has invalid Go header")
			}
			dir := path.Dir(input.File)
			if goInputsByDir[dir] == nil {
				goInputsByDir[dir] = make(map[string]nativeLayoutSourceInput)
			}
			goInputsByDir[dir][input.File] = input
		} else if !files[input.File] && path.Base(input.File) != "go.mod" {
			return fmt.Errorf("native-layout source inventory has an unrelated input %s", input.File)
		}
	}
	seenFiles := make(map[string]bool)
	usedInputs := make(map[string]bool)
	for _, selection := range plan.Selections {
		file := selection.Assembly.File
		if !files[file] || seenFiles[file] || !validNativeLayoutInput(selection.Assembly) {
			return fmt.Errorf("native-layout plan has missing, duplicate or invalid source input %s", file)
		}
		seenFiles[file] = true
		if input, exists := inputs[file]; !exists || input != selection.Assembly {
			return fmt.Errorf("native-layout assembly selection differs from source inventory")
		}
		usedInputs[file] = true
		goInputs := goInputsByDir[path.Dir(file)]
		if len(selection.GoFiles) != len(goInputs) {
			return fmt.Errorf("native-layout selection omits captured Go constraint inputs")
		}
		for _, input := range selection.GoFiles {
			if captured, exists := goInputs[input.File]; !exists || captured != input {
				return fmt.Errorf("native-layout Go selection differs from source inventory")
			}
			usedInputs[input.File] = true
		}
		if file == result.NativeLayout.AsmFile && selection.Assembly.SHA256 != result.NativeLayout.SourceSHA256 {
			return fmt.Errorf("native-layout plan differs from pinned source hash")
		}
		if selection.ExcludedKind != "" {
			if selection.ExcludedReason == "" || len(selection.Decisions) != 0 {
				return fmt.Errorf("native-layout excluded source lacks independent reason")
			}
			switch selection.ExcludedKind {
			case nativeLayoutIgnoredDirectory:
				if !discoveryDirIsIgnored(path.Dir(file)) {
					return fmt.Errorf("native-layout source is not in a Go-ignored directory")
				}
			case nativeLayoutNestedModule:
				input := selection.NestedModule
				if input == nil || !validNativeLayoutInput(*input) || path.Base(input.File) != "go.mod" ||
					path.Dir(input.File) == "." || !strings.HasPrefix(file, path.Dir(input.File)+"/") {
					return fmt.Errorf("native-layout nested exclusion lacks nested module input")
				}
				if captured, exists := inputs[input.File]; !exists || captured != *input {
					return fmt.Errorf("native-layout nested module differs from source inventory")
				}
				usedInputs[input.File] = true
			case discoverySourceNotApplicableNoGoPackage:
				if len(selection.GoFiles) != 0 {
					return fmt.Errorf("native-layout no-package exclusion has accepted Go source")
				}
				for target := range targets {
					preSourceNA[nativeLayoutKey(file, target, nil)] = selection.ExcludedKind
				}
			default:
				return fmt.Errorf("invalid native-layout source exclusion %s", selection.ExcludedKind)
			}
			continue
		}
		if selection.ExcludedReason != "" || selection.NestedModule != nil || len(selection.GoFiles) == 0 {
			return fmt.Errorf("native-layout selectable source lacks Go inputs or has stray exclusion evidence")
		}
		matches, err := nativeLayoutSelectionMatches(plan, selection)
		if err != nil {
			return err
		}
		seenTargets := make(map[string]bool)
		for _, decision := range selection.Decisions {
			if !targets[decision.Target] || seenTargets[decision.Target] {
				return fmt.Errorf("duplicate or out-of-matrix native-layout source decision")
			}
			seenTargets[decision.Target] = true
			matchTags, matches := matches[decision.Target]
			if !equalDiscoveryStrings(matchTags, decision.BuildTags) ||
				(matches && decision.Kind == nativeLayoutBuildConstraints) ||
				(!matches && decision.Kind != nativeLayoutBuildConstraints) {
				return fmt.Errorf("native-layout selection disagrees with source constraints for %s on %s", file, decision.Target)
			}
			key := nativeLayoutKey(file, decision.Target, decision.BuildTags)
			switch decision.Kind {
			case nativeLayoutSelected:
				if decision.Reason != "" {
					return fmt.Errorf("selected native-layout source carries exclusion reason")
				}
				selected[key] = true
			case nativeLayoutBuildConstraints, nativeLayoutGoAssemblerTarget, discoverySourceNotApplicableNoSymbols:
				if strings.TrimSpace(decision.Reason) == "" {
					return fmt.Errorf("native-layout source exclusion lacks reason")
				}
				if decision.Kind != nativeLayoutBuildConstraints {
					preSourceNA[key] = decision.Kind
				}
			default:
				return fmt.Errorf("invalid native-layout source decision %s", decision.Kind)
			}
		}
		if len(seenTargets) != len(targets) {
			return fmt.Errorf("native-layout plan omits source target decisions for %s", file)
		}
	}
	if len(seenFiles) != len(files) {
		return fmt.Errorf("native-layout plan does not cover the discovered source inventory")
	}
	if len(usedInputs) != len(inputs) {
		return fmt.Errorf("native-layout source inventory contains unaccounted inputs")
	}
	planned, err := nativeLayoutConfigurationKeys(plan.BuildConfigurations, files, targets)
	if err != nil {
		return err
	}
	if len(planned) != len(selected) {
		return fmt.Errorf("native-layout pre-filter plan differs from source selection")
	}
	for key := range selected {
		if !planned[key] {
			return fmt.Errorf("native-layout pre-filter plan omits selected source %v", key)
		}
	}
	filtered, active, err := filterNativeLayoutConfigurations(plan.BuildConfigurations, *result.NativeLayout)
	if err != nil || !active {
		return fmt.Errorf("native-layout plan does not justify exact pinned filter: %v", err)
	}
	required, err := nativeLayoutConfigurationKeys(filtered, files, targets)
	if err != nil {
		return err
	}
	executed, err := nativeLayoutConfigurationKeys(result.BuildConfigurations, files, targets)
	if err != nil {
		return err
	}
	for key := range executed {
		if !required[key] {
			return fmt.Errorf("native-layout execution claims an unplanned or pinned source %v", key)
		}
	}
	if err := validateDiscoverySourceNotApplicableEvidence(result); err != nil {
		return err
	}
	sourceNA := make(map[nativeLayoutPlanKey]bool)
	for _, item := range result.SourceNotApplicableItems {
		itemFiles := append(append([]string(nil), item.AsmFiles...), item.AsmFile)
		for _, file := range itemFiles {
			if file == "" {
				continue
			}
			for _, target := range item.Targets {
				key := nativeLayoutKey(file, target, item.BuildTags)
				valid := preSourceNA[key] == item.Kind || required[key] &&
					(item.Kind == discoverySourceNotApplicableGoBuild || item.Kind == discoverySourceNotApplicableAsmDecl)
				if !valid || sourceNA[key] || executed[key] {
					return fmt.Errorf("native-layout source N/A has unplanned, duplicate or executed scope %v", key)
				}
				sourceNA[key] = true
			}
		}
	}
	for key := range preSourceNA {
		if !sourceNA[key] {
			return fmt.Errorf("native-layout pre-filter exclusion lacks structured source N/A %v", key)
		}
	}
	for key := range required {
		if !executed[key] && !sourceNA[key] {
			return fmt.Errorf("native-layout remainder was neither executed nor source N/A: %v", key)
		}
	}
	if result.NotApplicableTranslations != len(result.NotApplicableItems) {
		return fmt.Errorf("native-layout target N/A count lacks per-file evidence")
	}
	targetNA, err := summarizeDiscoveryTargetSkips(discoveryCandidate{AsmFiles: result.DiscoveredAsmFiles}, result.NotApplicableItems)
	if err != nil {
		return err
	}
	seenTargetNA := make(map[nativeLayoutPlanKey]bool)
	for _, item := range targetNA {
		if item.Kind != targetNotApplicableGoTextArgSize || item.Symbol == "" || item.PkgPath == "" || item.DeclaredArgSize == item.ExpectedArgSize {
			return fmt.Errorf("native-layout target N/A has invalid ABI evidence")
		}
		found := false
		for key := range executed {
			if key.File == item.AsmFile && key.Target == item.Target {
				if seenTargetNA[key] {
					return fmt.Errorf("duplicate native-layout target N/A")
				}
				seenTargetNA[key], found = true, true
			}
		}
		if !found {
			return fmt.Errorf("native-layout target N/A claims an unexecuted or pinned file")
		}
	}
	if result.Translations+result.NotApplicableTranslations != len(executed) ||
		!equalDiscoveryStrings(result.ApplicableAsmFiles, discoveryConfigurationAsmFiles(result.BuildConfigurations)) {
		return fmt.Errorf("native-layout execution counts or file union disagree with the validated remainder")
	}
	return nil
}
