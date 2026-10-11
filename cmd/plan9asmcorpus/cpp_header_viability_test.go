package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

func TestCPPHeaderViabilityReuseKeepsExactScopesAndFinalChecks(t *testing.T) {
	var cache discoveryHeaderViabilityCache
	checks, guards := 0, 0
	run := func() error { checks++; return nil }
	verify := func() error { guards++; return nil }
	key := discoveryHeaderViabilityKey("profile-one", "example.invalid/p", []string{"custom"})
	for repeat := 0; repeat < 20; repeat++ {
		if err := cache.check(key, verify, run, nil); err != nil {
			t.Fatal(err)
		}
	}
	if checks != 1 || guards != 40 {
		t.Fatalf("20 exact queries compiled %d times with %d guards, want 1 compile and 40 source/lifetime guards", checks, guards)
	}
	for _, other := range []string{
		discoveryHeaderViabilityKey("profile-two", "example.invalid/p", []string{"custom"}),
		discoveryHeaderViabilityKey("profile-one", "example.invalid/sibling", []string{"custom"}),
		discoveryHeaderViabilityKey("profile-one", "example.invalid/p", []string{"different"}),
	} {
		if err := cache.check(other, verify, run, nil); err != nil {
			t.Fatal(err)
		}
	}
	if checks != 4 {
		t.Fatal("another actual tool/profile, package or tag borrowed a prior check")
	}
	if err := run(); err != nil || checks != 5 {
		t.Fatal("mandatory final checks cannot consume a planning cache entry")
	}
}

func TestCPPHeaderViabilityNeverDefersUnprovedOrMixedFailures(t *testing.T) {
	// This observed exit supplies only the command-status unit-test input.
	// Mutated diagnostics below are not original-Go source/pass evidence.
	exit := discoveryAsmDeclObservedExitOne(t)
	receipt := func(cause error, diagnostic string) error {
		return &discoveryCapturedCommandError{command: "trusted-go list -export", cause: cause, output: diagnostic}
	}
	const source = "source.go:3:2: undefined: MissingOriginalValue"
	valid := receipt(exit, source)
	for _, test := range []struct {
		name string
		err  error
	}{
		{"unobserved diagnostic", errors.New(source)},
		{"unknown exit", receipt(&exec.ExitError{}, source)},
		{"missing source", receipt(exit, "package compile failed")},
		{"infrastructure", receipt(exit, source+"\nno space left on device")},
		{"cancel", errors.Join(valid, context.Canceled)},
		{"cleanup", errors.Join(valid, errDiscoveryCommandCleanup)},
		{"owner", errors.Join(valid, &discoverySourceProofError{errors.New("owner changed")})},
		{"unknown companion", errors.Join(valid, errors.New("unexplained observer failure"))},
	} {
		t.Run(test.name, func(t *testing.T) {
			var cache discoveryHeaderViabilityCache
			calls := 0
			for repeat := 0; repeat < 2; repeat++ {
				err := cache.check("scope", func() error { return nil }, func() error { calls++; return test.err },
					func() error { t.Fatal("unproved failure reached source-rejection replay"); return nil })
				var unsupported *discoveryHeaderPlanningUnsupported
				if err == nil || errors.As(err, &unsupported) || len(cache.entries) != 0 {
					t.Fatalf("unproved failure was cached/deferred: %v", err)
				}
			}
			if calls != 2 {
				t.Fatal("ordinary failures were silently cached")
			}
		})
	}
	for _, axis := range []string{"cached source", "post source", "tool"} {
		t.Run(axis, func(t *testing.T) {
			var cache discoveryHeaderViabilityCache
			guards, calls, tools := 0, 0, 0
			verify := func() error { guards++; return nil }
			run := func() error { calls++; return valid }
			reobserve := func() error { tools++; return nil }
			for repeat := 0; repeat < 3; repeat++ {
				var unsupported *discoveryHeaderPlanningUnsupported
				if err := cache.check("scope", verify, run, reobserve); !errors.As(err, &unsupported) {
					t.Fatal(err)
				}
			}
			if calls != 1 || guards != 6 || tools != 3 {
				t.Fatalf("negative reuse lost guards: calls=%d guards=%d tools=%d", calls, guards, tools)
			}
			if axis == "tool" {
				reobserve = func() error { return errors.New("actual tool changed") }
			} else {
				guards = 0
				verify = func() error {
					guards++
					if axis == "cached source" || guards == 2 {
						return errors.New("original source/lifetime changed")
					}
					return nil
				}
			}
			var unsupported *discoveryHeaderPlanningUnsupported
			if err := cache.check("scope", verify, run, reobserve); err == nil || errors.As(err, &unsupported) || len(cache.entries) != 0 {
				t.Fatalf("changed %s retained fallback authority: %v", axis, err)
			}
		})
	}
}

func TestCPPHeaderViabilityBoundsOnlyDisableReuse(t *testing.T) {
	for _, cache := range []discoveryHeaderViabilityCache{
		{bytes: discoveryHeaderPreflightByteLimit},
		{entries: make(map[string]string)},
	} {
		if cache.bytes == 0 {
			for index := 0; index < discoveryHeaderPreflightEntryLimit; index++ {
				cache.entries[fmt.Sprint(index)] = ""
			}
		}
		calls := 0
		for repeat := 0; repeat < 2; repeat++ {
			if err := cache.check(strings.Repeat("x", 32), func() error { return nil }, func() error { calls++; return nil }, nil); err != nil {
				t.Fatal(err)
			}
		}
		if calls != 2 {
			t.Fatal("a full bounded cache must do fresh work, not skip a source scope")
		}
	}
}
