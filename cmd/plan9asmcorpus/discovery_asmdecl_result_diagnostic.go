package main

import (
	"strconv"
	"strings"
)

// This is a failure-only display reason, not a source rejection or a result
// certificate. Keep the original actual command receipt and all existing
// source/Wait/batch guards; arbitrary wrappers and joins do not qualify.
func discoveryAsmDeclOnlyUnprovedResults(moduleDir string, files []string, err error) bool {
	failures, observed := discoveryAsmDeclObservedFailures(err)
	if !observed || isDiscoveryInfrastructureFailure(err) ||
		!discoveryAsmDeclLocationsBelongToCandidate(moduleDir, files, err) {
		return false
	}
	type resultLocation struct {
		file, arch, symbol, offset string
	}
	for _, failure := range failures {
		results := make(map[resultLocation]bool)
		var aliases []resultLocation
		for _, line := range strings.Split(failure.output, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || discoveryAsmDeclPackageHeading.MatchString(line) {
				continue
			}
			position := discoveryAsmDeclPosition(line)
			if position == nil {
				return false
			}
			if result := discoveryAsmDeclUnwrittenResult.FindStringSubmatch(position[6]); result != nil {
				width, widthErr := strconv.ParseInt(result[1], 10, 64)
				_, offsetErr := strconv.ParseInt(result[2], 10, 64)
				if widthErr != nil || width <= 0 || offsetErr != nil {
					return false
				}
				results[resultLocation{position[1], position[4], position[5], result[2]}] = true
				continue
			}
			alias := discoveryAsmDeclResolvedNameWarning.FindStringSubmatch(position[6])
			if alias == nil || !discoveryAsmDeclKnownNonABIWarning(line) ||
				!strings.HasSuffix(position[6], " is ret+"+alias[2]+"(FP)") {
				return false
			}
			aliases = append(aliases, resultLocation{position[1], position[4], position[5], alias[2]})
		}
		if len(results) == 0 {
			return false
		}
		// A textual result alias can accompany the same still-unproved RET,
		// but another function/offset's warning is a mixed failure. Nothing is
		// removed and no alias proof that failed earlier is relaxed here.
		for _, alias := range aliases {
			if !results[alias] {
				return false
			}
		}
	}
	return true
}
