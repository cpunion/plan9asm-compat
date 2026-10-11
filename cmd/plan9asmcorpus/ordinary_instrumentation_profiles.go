package main

import "go/build/constraint"

// Ordinary profiles compile non-test packages with CGO disabled and without
// instrumentation flags. CPU/experiment/custom predicates stay unassigned:
// this rejects a Go partner only if no such ordinary profile can select it.
// Assembly predicates are deliberately not pruned this way. An assembly file
// requiring instrumentation needs an actual separate driver contract, not N/A.
func ordinaryInstrumentationGoPartnerMayMatch(expr constraint.Expr) bool {
	return discoveryExpressionMayMatch(expr, map[string]bool{
		"race": false,
		"msan": false,
		"asan": false,
	})
}
