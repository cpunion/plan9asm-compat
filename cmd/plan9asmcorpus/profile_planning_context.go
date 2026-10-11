package main

import (
	"context"
	"fmt"
)

// Producers pass their operation context through CPU-only planning loops.
// Offline source replay remains deterministic without a live context. Never
// retain a producer context in portable plans: setup and target budgets differ.
func checkDiscoveryProfilePlanningContext(contexts []context.Context) error {
	if len(contexts) > 1 || len(contexts) == 1 && contexts[0] == nil {
		return fmt.Errorf("profile planning requires at most one nonnil operation context")
	}
	if len(contexts) == 1 {
		return contexts[0].Err()
	}
	return nil
}
