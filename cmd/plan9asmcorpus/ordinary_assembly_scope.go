package main

import (
	"fmt"
	"path"
	"strings"
)

const ordinarySelectionScopeProtocol = "exact_source_matchfile_v2"

// Discovery remains an immutable historical inventory. The v2 tested scope
// closes its package directories over every original nonempty assembly sibling,
// before target/profile/custom-tag selection and before CPP registration.
func deriveOrdinaryAssemblyScope(plan *discoveryOrdinarySelectionPlan, discovered []string) ([]string, error) {
	if len(discovered) == 0 {
		return nil, fmt.Errorf("ordinary tested scope requires a discovered inventory")
	}
	sources, directories, err := ordinarySelectionBytes(plan)
	if err != nil {
		return nil, err
	}
	packageDirs, scope := make(map[string]bool), make(map[string]bool)
	for _, file := range discovered {
		if !ordinarySelectionLocalPath(file) || !strings.HasSuffix(file, ".s") || scope[file] {
			return nil, fmt.Errorf("invalid discovered assembly in tested scope: %s", file)
		}
		if _, found := sources[file]; !found {
			return nil, fmt.Errorf("discovered assembly lacks original source witness: %s", file)
		}
		packageDirs[path.Dir(file)], scope[file] = true, true
	}
	digests := make(map[string]string)
	for _, source := range plan.Sources {
		digests[source.File] = source.SHA256
	}
	emptyDigest := discoveryFeatureBytesSHA256(nil)
	for dir := range packageDirs {
		for name, kind := range directories[dir] {
			if kind != "file" || !strings.HasSuffix(name, ".s") {
				continue
			}
			file := path.Join(dir, name)
			if _, found := sources[file]; !found {
				return nil, fmt.Errorf("complete package directory lacks assembly source witness: %s", file)
			}
			// Both full-byte hashes were checked by ordinarySelectionBytes.
			// Whitespace, comments and macro-empty files are not zero-byte
			// allowances: they must receive actual Go and LLVM object proofs.
			if digests[file] != emptyDigest {
				scope[file] = true
			}
		}
	}
	if len(scope) > 512 {
		return nil, fmt.Errorf("ordinary tested assembly scope exceeds its source bound (not N/A)")
	}
	return sortedDiscoverySet(scope), nil
}

func ordinarySelectionTestedAssembly(plan *discoveryOrdinarySelectionPlan, discovered []string) ([]string, error) {
	if plan == nil {
		return nil, fmt.Errorf("missing original ordinary assembly scope")
	}
	switch plan.Protocol {
	case ordinarySelectionProtocol:
		if len(plan.TestedAsmFiles) != 0 {
			return nil, fmt.Errorf("legacy ordinary selection cannot claim a v2 tested scope")
		}
		return append([]string(nil), discovered...), nil
	case ordinarySelectionScopeProtocol:
		derived, err := deriveOrdinaryAssemblyScope(plan, discovered)
		if err != nil {
			return nil, err
		}
		if !equalDiscoveryStrings(plan.TestedAsmFiles, derived) {
			return nil, fmt.Errorf("ordinary tested assembly scope differs from the original package-directory union")
		}
		return derived, nil
	default:
		return nil, fmt.Errorf("unknown ordinary assembly scope protocol %q", plan.Protocol)
	}
}

func discoveryResultAssemblyScope(result discoveryCorpusResult) ([]string, error) {
	if result.OrdinarySelectionPlan == nil {
		return append([]string(nil), result.DiscoveredAsmFiles...), nil
	}
	return ordinarySelectionTestedAssembly(result.OrdinarySelectionPlan, result.DiscoveredAsmFiles)
}
