package main

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/mod/sumdb/dirhash"
)

const discoveryReplayCPPInputsProtocol = "exact_go_cpp_original_replay_v3"
const discoveryReplayCPPGraphBytes = 64 << 20

// The projection discovers raw controls/resources only. Its full original is
// replayed by the shared executor; these controls are never executed as a
// substitute macro program. Physical and recorded macro strings stay distinct.
func discoveryReplayCPPSource(file string, data []byte) (discoveryCPPSource, error) {
	return discoveryReplayCPPSourceText(file, string(data))
}

// Keep immutable text by value. The parameter owns a separate string slot;
// no public *string or directive slice becomes part of the private parse.
// Sharing backing bytes also makes repeated equality checks inexpensive.
func discoveryReplayCPPSourceText(file, text string) (discoveryCPPSource, error) {
	result := discoveryCPPSource{
		File: file, SHA256: discoveryFeatureBytesSHA256([]byte(text)), Original: &text,
		Directives: []discoveryCPPDirective{},
	}
	physical, err := plan9asm.InspectAssemblyCPPSource(text, file, nil)
	if err != nil {
		return result, err
	}
	for _, record := range physical.Records {
		tokens := record.Tokens
		for index := 0; index+1 < len(tokens); index++ {
			if tokens[index].Text != "#" || tokens[index+1].Kind != "identifier" {
				continue
			}
			kind := tokens[index+1].Text
			directive := discoveryCPPDirective{Line: tokens[index].Line, Kind: kind,
				Generated: record.Definition != nil && index != 0}
			switch kind {
			case "define", "undef", "ifdef", "ifndef":
				if index+2 >= len(tokens) || tokens[index+2].Kind != "identifier" {
					return result, fmt.Errorf("CPP original %s:%d: unclosed %s name", file, directive.Line, kind)
				}
				directive.Name = tokens[index+2].Text
			case "include":
				if index+2 >= len(tokens) || tokens[index+2].Kind != "string" {
					// Keep the unresolved physical control. A macro formal may
					// supply a String only during the original input-stack replay.
					// This is not C-style prescan of a physical include operand.
					break
				}
				literal := tokens[index+2].Text
				if record.Definition != nil && index != 0 {
					literal = tokens[index+2].RecordedValue
				}
				name, err := strconv.Unquote(literal)
				if err != nil || name == "" {
					return result, fmt.Errorf("CPP original %s:%d: invalid include candidate", file, directive.Line)
				}
				directive.Include = name
			case "else", "endif", "line":
			default:
				if len(result.Directives) == 0 && record.Definition == nil && index == 0 {
					return result, &discoveryUnsupportedCPPError{File: file, SHA256: result.SHA256, Directive: kind, Line: directive.Line}
				}
				return result, fmt.Errorf("CPP original %s:%d: unknown control %s", file, directive.Line, kind)
			}
			if len(result.Directives) >= discoveryCPPDirectiveLimit {
				return result, fmt.Errorf("CPP raw inventory exceeds its original control bound")
			}
			result.Directives = append(result.Directives, directive)
		}
	}
	candidates, err := discoveryCPPStringCandidates(text, file, result.Directives)
	if err != nil {
		return result, err
	}
	result.resourceIndex = &discoveryCPPSourceResourceIndex{
		file: file, sha256: result.SHA256, original: text,
		directives: append([]discoveryCPPDirective(nil), result.Directives...),
		candidates: candidates,
	}
	return result, nil
}

// Equality authenticates the complete public source projection. A private
// lexer optimization is not transport data and is never admission evidence.
func equalDiscoveryCPPSource(left, right discoveryCPPSource) bool {
	left.resourceIndex, right.resourceIndex = nil, nil
	return reflect.DeepEqual(left, right)
}

func captureDiscoveryReplayCPPInputs(plan *discoveryOrdinarySelectionPlan, moduleDir, goRoot string, files []string, deferred bool, contexts ...context.Context) (*discoveryCPPInputs, error) {
	if plan == nil || !filepath.IsAbs(moduleDir) || !filepath.IsAbs(goRoot) ||
		len(files) == 0 || len(files) > 512 || len(contexts) > 1 || len(contexts) == 1 && contexts[0] == nil {
		return nil, fmt.Errorf("full CPP capture lacks bounded actual source context")
	}
	check := func() error {
		if len(contexts) != 0 {
			return contexts[0].Err()
		}
		return nil
	}
	registration, err := captureDiscoveryCPPRegistration(goRoot, plan.GoVersion)
	if err != nil {
		return nil, err
	}
	inputs := &discoveryCPPInputs{
		Protocol: discoveryReplayCPPInputsProtocol, Module: plan.Module, Version: plan.Version,
		ModuleSum: plan.ModuleSum, ZipSHA256: plan.ZipSHA256, Registration: registration,
		Sources: make(map[string]discoveryCPPSource), Units: []discoveryCPPUnit{},
	}
	total := 0
	for _, assembly := range files {
		unit := discoveryCPPUnit{
			File: assembly, Includes: make(map[string]string), DeferredIncludes: make(map[string]string),
		}
		seen := make(map[string]bool)
		var capture func(string, int) error
		capture = func(id string, depth int) error {
			if err := check(); err != nil {
				return err
			}
			if seen[id] {
				return nil
			}
			if depth > 32 {
				return fmt.Errorf("CPP original graph exceeds its nesting bound")
			}
			origin, relative, err := discoveryCPPSourceIdentity(id)
			if err != nil {
				return err
			}
			root := moduleDir
			if origin == "tool" {
				root = goRoot
			}
			name := filepath.Join(root, filepath.FromSlash(relative))
			if err := discoveryCPPRegularSource(root, name); err != nil {
				return err
			}
			file, err := os.Open(name)
			if err != nil {
				return err
			}
			data, readErr := io.ReadAll(io.LimitReader(file, discoveryReplayCPPGraphBytes+1))
			closeErr := file.Close()
			if readErr != nil || closeErr != nil {
				return fmt.Errorf("read original CPP: %v (close: %v)", readErr, closeErr)
			}
			if depth == 0 {
				if rejection := preCPPFirstTokenRejection(relative, data); rejection != nil {
					return rejection
				}
			}
			source, err := discoveryReplayCPPSource(relative, data)
			if err != nil {
				return err
			}
			if previous, found := inputs.Sources[id]; found {
				if !equalDiscoveryCPPSource(previous, source) {
					return fmt.Errorf("CPP original changed between units: %s", id)
				}
			} else {
				if len(inputs.Sources) >= 512 || len(data) > discoveryReplayCPPGraphBytes-total {
					return fmt.Errorf("CPP original graph exceeds its file/byte bounds")
				}
				total += len(data)
				inputs.Sources[id] = source
			}
			seen[id] = true
			resources, err := discoveryCPPRegisteredResources(inputs, source)
			if err != nil {
				return err
			}
			for _, resource := range resources {
				directive, key := resource.directive, id+resource.key
				target, deferredKind, err := discoveryCPPResolveOriginalResource(moduleDir, goRoot, assembly, resource, deferred)
				if err != nil {
					return err
				}
				if deferredKind != "" {
					unit.DeferredIncludes[key] = deferredKind
					continue
				}
				module, tool, err := gotoolprofile.CPPIncludeCandidates(assembly, directive.Include)
				if err != nil {
					return err
				}
				if !gotoolprofile.CPPLocalSource(module) {
					miss := gotoolprofile.CPPPackageSearchMiss{
						Protocol: gotoolprofile.CPPPackageSearchMissProtocol, Assembly: assembly,
						Source: id, Include: directive.Include, PackageCandidate: module, ToolSource: tool,
					}
					if directive.Generated {
						miss.Protocol, miss.Source = gotoolprofile.CPPExpandedPackageSearchMissProtocol, ""
					}
					if err := gotoolprofile.VerifyCPPPackageSearchMiss(miss, moduleDir, goRoot); err != nil {
						return err
					}
					if unit.PackageSearchMisses == nil {
						unit.PackageSearchMisses = make(map[string]gotoolprofile.CPPPackageSearchMiss)
					}
					unit.PackageSearchMisses[key] = miss
				}
				unit.Includes[key] = target
				if err := capture(target, depth+1); err != nil {
					return err
				}
			}
			return nil
		}
		if err := capture("module/"+assembly, 0); err != nil {
			return nil, err
		}
		inputs.Units = append(inputs.Units, unit)
	}
	sort.Slice(inputs.Units, func(i, j int) bool { return inputs.Units[i].File < inputs.Units[j].File })
	if err := validateDiscoveryReplayCPPInputs(inputs, plan, files); err != nil {
		return nil, err
	}
	if err := verifyDiscoveryCPPInputsUnchanged(inputs, moduleDir, goRoot); err != nil {
		return nil, err
	}
	return inputs, nil
}

func discoveryReplayCPPUnitRegistration(inputs *discoveryCPPInputs, unit discoveryCPPUnit, used map[string]bool) ([]discoveryCPPDirective, error) {
	// Resource registration is finite and independent of execution or branch
	// activity. The executor later supplies its own complete active used set.
	return discoveryDeferredCPPUnitRegistration(inputs, unit, used)
}

func validateDiscoveryReplayCPPInputs(inputs *discoveryCPPInputs, plan *discoveryOrdinarySelectionPlan, files []string) error {
	return validateDiscoveryReplayCPPInputsWithIndex(inputs, plan, files, nil)
}

func validateDiscoveryReplayCPPInputsWithIndex(inputs *discoveryCPPInputs, plan *discoveryOrdinarySelectionPlan,
	files []string, sourceIndex *discoveryCPPPlanningSourceIndex) error {
	_, err := validatedDiscoveryReplayCPPInputsWithIndex(inputs, plan, files, sourceIndex)
	return err
}

func validatedDiscoveryReplayCPPInputsWithIndex(inputs *discoveryCPPInputs, plan *discoveryOrdinarySelectionPlan,
	files []string, sourceIndex *discoveryCPPPlanningSourceIndex) (*discoveryCPPInputs, error) {
	if plan == nil || inputs == nil || inputs.Module != plan.Module || inputs.Version != plan.Version ||
		inputs.ModuleSum != plan.ModuleSum || inputs.ZipSHA256 != plan.ZipSHA256 ||
		len(inputs.Sources) == 0 || len(inputs.Sources) > 512 {
		return nil, fmt.Errorf("full CPP graph differs from original archive scope")
	}
	indexed, err := indexDiscoveryReplayCPPSources(inputs, sourceIndex)
	if err != nil {
		return nil, err
	}
	// The same structural origin/edge checks retain physical source positions.
	// New full replay never borrows the historical control executor.
	if err := validateDiscoveryCPPInputStructure(indexed, plan, files); err != nil {
		return nil, err
	}
	return indexed, nil
}

// Each query owns a fresh source map. Reuse only pure parses, never a previous
// projection or graph validation. This also lets offline planning use bounded
// private resource indexes after JSON has deliberately discarded them.
func indexDiscoveryReplayCPPSources(inputs *discoveryCPPInputs, sourceIndex *discoveryCPPPlanningSourceIndex) (*discoveryCPPInputs, error) {
	if inputs == nil || inputs.Protocol != discoveryReplayCPPInputsProtocol ||
		len(inputs.Sources) == 0 || len(inputs.Sources) > 512 {
		return nil, fmt.Errorf("full CPP source indexing lacks a bounded original graph")
	}
	// JSON deliberately has no private lexer indexes. Reuse only the indexes
	// derived below from complete original-source parses. The planner may own
	// a same-call pure parser index; ordinary validators receive nil and parse
	// from scratch. Neither path reuses validation receipts: every public
	// source/edge check still runs on every invocation.
	indexed := *inputs
	indexed.Sources = make(map[string]discoveryCPPSource, len(inputs.Sources))
	total := 0
	for id, source := range inputs.Sources {
		_, file, err := discoveryCPPSourceIdentity(id)
		if err != nil || source.Original == nil || len(*source.Original) > discoveryReplayCPPGraphBytes-total {
			return nil, fmt.Errorf("full CPP source is missing or unbounded: %s", id)
		}
		total += len(*source.Original)
		resources, err := sourceIndex.validate(file, source)
		if err != nil {
			return nil, fmt.Errorf("CPP raw inventory/full SHA differs from original replay: %s: %v", id, err)
		}
		source.resourceIndex = resources
		indexed.Sources[id] = source
	}
	return &indexed, nil
}

func verifyDiscoveryReplayCPPZIP(inputs *discoveryCPPInputs, plan *discoveryOrdinarySelectionPlan, archivePath string) error {
	var files []string
	for _, unit := range inputs.Units {
		files = append(files, unit.File)
	}
	if err := validateDiscoveryReplayCPPInputs(inputs, plan, files); err != nil {
		return err
	}
	digest, err := discoveryFeatureFileSHA256(archivePath)
	if err != nil || digest != inputs.ZipSHA256 {
		return fmt.Errorf("full CPP original archive bytes changed")
	}
	sum, err := dirhash.HashZip(archivePath, dirhash.Hash1)
	if err != nil || sum != inputs.ModuleSum {
		return fmt.Errorf("full CPP original archive h1 changed")
	}
	archive, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer archive.Close()
	members := make(map[string]*zip.File)
	prefix := inputs.Module + "@" + inputs.Version + "/"
	for _, member := range archive.File {
		if member.FileInfo().IsDir() {
			continue
		}
		file := strings.TrimPrefix(member.Name, prefix)
		if file == member.Name || !ordinarySelectionLocalPath(file) || members[file] != nil || !member.Mode().IsRegular() {
			return fmt.Errorf("full CPP archive has an unsafe/duplicate member")
		}
		members[file] = member
	}
	for id, source := range inputs.Sources {
		origin, file, _ := discoveryCPPSourceIdentity(id)
		if origin != "module" {
			continue
		}
		member := members[file]
		if member == nil || member.UncompressedSize64 > discoveryReplayCPPGraphBytes {
			return fmt.Errorf("full CPP source has no bounded archive member: %s", file)
		}
		reader, err := member.Open()
		if err != nil {
			return err
		}
		data, readErr := io.ReadAll(io.LimitReader(reader, discoveryReplayCPPGraphBytes+1))
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil || !bytes.Equal(data, []byte(*source.Original)) {
			return fmt.Errorf("CPP complete original bytes differ from archive member: %s", file)
		}
	}
	for _, unit := range inputs.Units {
		for id, source := range inputs.Sources {
			resources, err := discoveryCPPRegisteredResources(inputs, source)
			if err != nil {
				return err
			}
			for _, resource := range resources {
				directive, key := resource.directive, id+resource.key
				target, bound := unit.Includes[key]
				deferred := unit.DeferredIncludes[key]
				if !bound && deferred == "" {
					continue
				}
				module, tool, err := gotoolprofile.CPPIncludeCandidates(unit.File, directive.Include)
				if resource.candidate && deferred == "unresolved_candidate" && err != nil {
					continue // Unsafe raw Strings do not become an input permission.
				}
				if err != nil {
					return err
				}
				wanted := "tool/" + tool
				if members[module] != nil {
					wanted = "module/" + module
				}
				if deferred != "" {
					if members[module] != nil {
						return fmt.Errorf("deferred CPP edge omitted an original archive member")
					}
				} else if target != wanted {
					return fmt.Errorf("CPP include selected a different original archive/tool origin")
				}
			}
		}
	}
	return nil
}
