package main

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

// These are possible String operands, never synthetic literal controls. The
// actual input stack alone decides which, if any, are used by an include.
type discoveryCPPResource struct {
	key       string
	directive discoveryCPPDirective
	candidate bool
}

// The parser owns this immutable index for the lifetime of one captured source.
// It is neither serialized nor lazily populated by concurrent query readers.
// Every public input is compared before reuse; changed or restored originals
// use the ordinary lexer. The index grants no source or include authority.
type discoveryCPPSourceResourceIndex struct {
	file, sha256, original string
	directives             []discoveryCPPDirective
	candidates             []discoveryCPPDirective
}

func (index *discoveryCPPSourceResourceIndex) matches(source discoveryCPPSource) bool {
	if index == nil || source.Original == nil || index.file != source.File ||
		index.sha256 != source.SHA256 || index.original != *source.Original ||
		len(index.directives) != len(source.Directives) {
		return false
	}
	for position, directive := range source.Directives {
		if index.directives[position] != directive {
			return false
		}
	}
	return true
}

// Candidate roles are private and derived only from complete originals, not
// supplied by a public JSON marker. Physical literal keys retain their original
// indices; candidate keys cannot masquerade as those source positions.
func discoveryCPPRegisteredResources(inputs *discoveryCPPInputs, source discoveryCPPSource) ([]discoveryCPPResource, error) {
	result := []discoveryCPPResource{}
	for index, directive := range source.Directives {
		if directive.Kind == "include" && directive.Include != "" {
			result = append(result, discoveryCPPResource{key: "#" + strconv.Itoa(index), directive: directive})
		}
	}
	if inputs.Protocol != discoveryReplayCPPInputsProtocol {
		return result, nil
	}
	if source.Original == nil {
		return nil, fmt.Errorf("CPP resource query omitted complete original bytes")
	}
	var candidates []discoveryCPPDirective
	if source.resourceIndex.matches(source) {
		candidates = source.resourceIndex.candidates
	} else {
		var err error
		candidates, err = discoveryCPPStringCandidates(*source.Original, source.File, source.Directives)
		if err != nil {
			return nil, err
		}
	}
	for index, directive := range candidates {
		result = append(result, discoveryCPPResource{
			key: "?" + strconv.Itoa(index), directive: directive, candidate: true,
		})
	}
	return result, nil
}

func discoveryOriginalCPPUnitRegistration(inputs *discoveryCPPInputs, unit discoveryCPPUnit, used map[string]bool) ([]discoveryCPPDirective, error) {
	directives := []discoveryCPPDirective{}
	visited, edges := make(map[string]bool), make(map[string]bool)
	var visit func(string, int) error
	visit = func(id string, depth int) error {
		if visited[id] {
			return nil
		}
		source, found := inputs.Sources[id]
		if !found || depth > 32 {
			return fmt.Errorf("missing or unbounded full-original CPP registration")
		}
		visited[id], used[id] = true, true
		resources, err := discoveryCPPRegisteredResources(inputs, source)
		if err != nil {
			return err
		}
		consume := func(resource discoveryCPPResource) error {
			directive, key := resource.directive, id+resource.key
			target, bound := unit.Includes[key]
			kind, deferred := unit.DeferredIncludes[key]
			if bound == deferred {
				return fmt.Errorf("original CPP resource lacks one exact bound/deferred role")
			}
			edges[key] = true
			module, tool, err := gotoolprofile.CPPIncludeCandidates(unit.File, directive.Include)
			if resource.candidate && deferred && kind == "unresolved_candidate" {
				if err == nil && inputs.Sources["module/"+module].Original != nil {
					return fmt.Errorf("unresolved String candidate omitted a registered original")
				}
				return nil
			}
			if err != nil {
				return err
			}
			if deferred {
				if !gotoolprofile.CPPLocalSource(module) || !gotoolprofile.CPPLocalSource(tool) ||
					kind != "generated_go_asm" && kind != "unresolved_include" ||
					(kind == "generated_go_asm") != (path.Clean(directive.Include) == "go_asm.h") ||
					inputs.Sources["module/"+module].Original != nil {
					return fmt.Errorf("unrecognized or omitted original CPP deferred resource")
				}
				return nil
			}
			if !gotoolprofile.CPPLocalSource(module) || target != "module/"+module {
				if !gotoolprofile.CPPLocalSource(tool) || target != "tool/"+tool {
					return fmt.Errorf("original CPP resource differs from fixed search origins")
				}
			}
			if err := visit(target, depth+1); err != nil {
				return err
			}
			return nil
		}
		// Preserve the old physical-literal traversal order. Query candidates
		// are a separate resource closure, never replayed as fake directives.
		for index, directive := range source.Directives {
			if directive.Kind == "include" {
				if directive.Include != "" {
					if err := consume(discoveryCPPResource{key: "#" + strconv.Itoa(index), directive: directive}); err != nil {
						return err
					}
				}
				continue
			}
			if len(directives) >= 4096 {
				return fmt.Errorf("full-original CPP registration exceeds its control bound")
			}
			directives = append(directives, directive)
		}
		for _, resource := range resources {
			if resource.candidate {
				if err := consume(resource); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := visit("module/"+unit.File, 0); err != nil {
		return nil, err
	}
	if len(edges) != len(unit.Includes)+len(unit.DeferredIncludes) {
		return nil, fmt.Errorf("unexplained original CPP resource registration")
	}
	return directives, nil
}

func discoveryCPPStringCandidates(text, file string, existing []discoveryCPPDirective) ([]discoveryCPPDirective, error) {
	tokens, err := plan9asm.InspectAssemblyCPPStringTokens(text, file)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	for _, directive := range existing {
		if directive.Kind == "include" && directive.Include != "" {
			seen[directive.Include] = true
		}
	}
	result := []discoveryCPPDirective{}
	for _, token := range tokens {
		for _, spelling := range []string{token.Text, token.RecordedValue} {
			name, err := strconv.Unquote(spelling)
			if err != nil {
				return nil, fmt.Errorf("CPP String candidate has an invalid token projection: %w", err)
			}
			if name == "" || seen[name] || path.IsAbs(name) || strings.ContainsAny(name, ":\\\x00\r\n") {
				continue // No grant to unsafe operands; active use will still fail.
			}
			seen[name] = true
			result = append(result, discoveryCPPDirective{
				Line: token.Line, Kind: "include", Include: name, Generated: true,
			})
		}
	}
	return result, nil
}

// A DATA/String candidate need not be a file. Its missing/non-source role is
// explicit and remains unusable by ReplayCPPOriginal. Existing regular sources
// still require the exact package-CWD or canonical SDK source identity.
func discoveryCPPResolveOriginalResource(moduleDir, goRoot, assembly string, resource discoveryCPPResource, deferred bool) (string, string, error) {
	directive := resource.directive
	if !resource.candidate {
		return discoveryCPPResolveRawInclude(moduleDir, goRoot, assembly, directive.Include, deferred)
	}
	module, tool, err := gotoolprofile.CPPIncludeCandidates(assembly, directive.Include)
	if err != nil {
		return "", "unresolved_candidate", nil
	}
	preferred, err := gotoolprofile.CPPPreferredPackageInclude(moduleDir, assembly, directive.Include)
	if err != nil {
		return "", "", err
	}
	if info, err := os.Lstat(preferred); err == nil {
		if !gotoolprofile.CPPLocalSource(module) || !info.Mode().IsRegular() {
			return "", "unresolved_candidate", nil
		}
		if err := discoveryCPPRegularSource(moduleDir, preferred); err != nil {
			return "", "", err
		}
		return "module/" + module, "", nil
	} else if !os.IsNotExist(err) {
		return "", "", err
	}
	if path.Clean(directive.Include) == "go_asm.h" {
		return "", "generated_go_asm", nil
	}
	if !gotoolprofile.CPPLocalSource(tool) {
		return "", "unresolved_candidate", nil
	}
	name := filepath.Join(goRoot, filepath.FromSlash(tool))
	if info, err := os.Lstat(name); err == nil {
		if !info.Mode().IsRegular() {
			return "", "unresolved_candidate", nil
		}
		if _, err := gotoolprofile.CPPRegularSource(goRoot, tool); err != nil {
			return "", "", err
		}
		return "tool/" + tool, "", nil
	} else if !os.IsNotExist(err) {
		return "", "", err
	}
	return "", "unresolved_candidate", nil
}
