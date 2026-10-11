package main

import (
	"fmt"
	"path"
	"strconv"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

// This is an inventory walk, not a macro execution trace. Each original source
// and every include edge is registered once, including inactive controls and
// guarded cycles. Active source-order replay must be proved separately.
func discoveryDeferredCPPUnitRegistration(inputs *discoveryCPPInputs, unit discoveryCPPUnit, used map[string]bool) ([]discoveryCPPDirective, error) {
	if inputs.Protocol == discoveryReplayCPPInputsProtocol {
		return discoveryOriginalCPPUnitRegistration(inputs, unit, used)
	}
	var directives []discoveryCPPDirective
	visited, edges := make(map[string]bool), make(map[string]bool)
	var visit func(string, int) error
	visit = func(id string, depth int) error {
		if visited[id] {
			return nil
		}
		source, found := inputs.Sources[id]
		if !found || depth > 32 {
			return fmt.Errorf("missing or unbounded deferred CPP registration source")
		}
		visited[id], used[id] = true, true
		for index, directive := range source.Directives {
			if len(directives) >= 4096 {
				return fmt.Errorf("deferred CPP registration exceeds its control bound")
			}
			if directive.Kind != "include" {
				directives = append(directives, directive)
				continue
			}
			key := id + "#" + strconv.Itoa(index)
			target, bound := unit.Includes[key]
			kind, deferred := unit.DeferredIncludes[key]
			module, tool, err := gotoolprofile.CPPIncludeCandidates(unit.File, directive.Include)
			if err != nil || bound == deferred || deferred && (!ordinarySelectionLocalPath(module) || !ordinarySelectionLocalPath(tool)) {
				return fmt.Errorf("CPP include lacks one exact bound/deferred registration")
			}
			edges[key] = true
			if deferred {
				if kind != "generated_go_asm" && kind != "unresolved_include" || (kind == "generated_go_asm") != (path.Clean(directive.Include) == "go_asm.h") {
					return fmt.Errorf("unrecognized deferred CPP origin")
				}
				if _, exists := inputs.Sources["module/"+module]; exists {
					return fmt.Errorf("deferred CPP edge omitted a registered original source")
				}
				continue
			}
			// Only a selected tool origin needs the tool search's path bound.
			// Deferred edges still require both searches to be in scope above.
			if (!ordinarySelectionLocalPath(module) || target != "module/"+module) && (!ordinarySelectionLocalPath(tool) || target != "tool/"+tool) {
				return fmt.Errorf("deferred CPP binding differs from Go package/tool search")
			}
			if err := visit(target, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := visit("module/"+unit.File, 0); err != nil {
		return nil, err
	}
	if len(edges) != len(unit.Includes)+len(unit.DeferredIncludes) {
		return nil, fmt.Errorf("unexplained deferred CPP include registration")
	}
	return directives, nil
}

// Replay only definedness and active include bindings from compact original
// controls. Instruction bytes/expanded hashes still depend on the independently
// observed compiler consumer; this does not manufacture translation evidence.
func discoveryDeferredCPPConsumption(inputs *discoveryCPPInputs, unit discoveryCPPUnit, header *gotoolprofile.GeneratedHeaderProof, defines []string) (map[string]string, error) {
	if inputs.Protocol == discoveryReplayCPPInputsProtocol {
		_, consumed, err := replayDiscoveryOriginalCPP(inputs, unit, header, defines)
		return consumed, err
	}
	macros, consumed := make(map[string]bool), make(map[string]string)
	for _, name := range defines {
		macros[name] = true
	}
	type frame struct{ outer, branch bool }
	var stack []frame
	active, steps := true, 0
	var visit func(string, int) error
	visit = func(id string, depth int) error {
		source, found := inputs.Sources[id]
		if !found || depth > 32 {
			return fmt.Errorf("active CPP expansion has no bounded original source")
		}
		consumed[id] = source.SHA256
		for index, directive := range source.Directives {
			steps++
			if steps > 4096 {
				return fmt.Errorf("active CPP expansion exceeds its control bound")
			}
			switch directive.Kind {
			case "ifdef", "ifndef":
				if len(stack) >= 32 {
					return fmt.Errorf("active CPP condition nesting exceeds its bound")
				}
				branch := macros[directive.Name]
				if directive.Kind == "ifndef" {
					branch = !branch
				}
				stack = append(stack, frame{outer: active, branch: branch})
				active = active && branch
			case "else":
				if len(stack) == 0 {
					return fmt.Errorf("unmatched active CPP else")
				}
				top := &stack[len(stack)-1]
				top.branch = !top.branch
				active = top.outer && top.branch
			case "endif":
				if len(stack) == 0 {
					return fmt.Errorf("unmatched active CPP endif")
				}
				active = stack[len(stack)-1].outer
				stack = stack[:len(stack)-1]
			case "define":
				if active {
					if macros[directive.Name] {
						return fmt.Errorf("active CPP macro redefinition")
					}
					macros[directive.Name] = true
				}
			case "undef":
				if active {
					if !macros[directive.Name] {
						return fmt.Errorf("active CPP undef lacks an existing macro")
					}
					delete(macros, directive.Name)
				}
			case "include":
				if !active {
					continue
				}
				key := id + "#" + strconv.Itoa(index)
				if target, bound := unit.Includes[key]; bound {
					if err := visit(target, depth+1); err != nil {
						return err
					}
					continue
				}
				if unit.DeferredIncludes[key] != "generated_go_asm" || header == nil || header.Definitions == nil {
					return fmt.Errorf("active deferred include lacks actual full generated-header origin: %s", directive.Include)
				}
				data, err := gotoolprofile.CanonicalGeneratedHeader(header.Definitions)
				if err != nil {
					return err
				}
				consumed["generated/"+header.PackagePath+"/go_asm.h"] = discoveryFeatureBytesSHA256(data)
				for name := range header.Definitions {
					if macros[name] {
						return fmt.Errorf("actual generated header redefines an active original macro")
					}
					macros[name] = true
				}
			case "line":
			default:
				return fmt.Errorf("unregistered active CPP control")
			}
		}
		return nil
	}
	if err := visit("module/"+unit.File, 0); err != nil {
		return nil, err
	}
	if len(stack) != 0 {
		return nil, fmt.Errorf("unclosed active CPP condition")
	}
	return consumed, nil
}
