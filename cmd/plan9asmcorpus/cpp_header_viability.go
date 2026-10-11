package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
)

// One synchronous candidate planner owns this bounded cache. The actual
// profile includes compiler/environment/source identities; assembly siblings
// may share the same package check, but different CPU profiles may not.
// These entries never enter reports or replace final source/object checks.
type discoveryHeaderViabilityCache struct {
	entries map[string]string
	bytes   int
}

func discoveryHeaderViabilityKey(profile, pattern string, tags []string) string {
	data, _ := json.Marshal(struct {
		Profile string
		Pattern string
		Tags    []string
	}{profile, pattern, tags})
	return string(data)
}

func (cache *discoveryHeaderViabilityCache) check(key string, verify func() error,
	run func() error, reobserveRejected func() error) (result error) {
	if err := verify(); err != nil {
		cache.remove(key)
		return err
	}
	defer func() {
		if err := verify(); err != nil {
			cache.remove(key)
			// Joined source/lifetime failures must not expose a catchable
			// Unsupported child to the conservative planning fallback.
			var unsupported *discoveryHeaderPlanningUnsupported
			if errors.As(result, &unsupported) {
				result = fmt.Errorf("original package viability: %s", result)
			}
			result = errors.Join(result, err)
		}
	}()
	diagnostic, found := cache.entries[key]
	if !found {
		err := run()
		if err != nil {
			if isDiscoveryInfrastructureFailure(err) || !discoveryHeaderViabilitySourceExit(err) {
				return err
			}
			diagnostic = discoveryCommandDiagnostic(err)
			if !hasDiscoveryConcreteSourceDiagnostic(diagnostic) {
				return err
			}
		}
	}
	if diagnostic != "" {
		// Failed packages do not reach the metadata consumer's independent
		// tool replay. Reobserve here before deferring to final package checks.
		if err := reobserveRejected(); err != nil {
			cache.remove(key)
			return err
		}
		result = &discoveryHeaderPlanningUnsupported{
			reason: "original Go package rejection defers native header planning only; final source checks remain required:\n" + diagnostic,
		}
	}
	if !found && len(cache.entries) < discoveryHeaderPreflightEntryLimit &&
		len(key)+len(diagnostic) <= discoveryHeaderPreflightByteLimit-cache.bytes {
		if cache.entries == nil {
			cache.entries = make(map[string]string)
		}
		cache.entries[key] = diagnostic
		cache.bytes += len(key) + len(diagnostic)
	}
	return result
}

// The command receipt must be the only cause. A source diagnostic alongside
// an unrelated owner, cleanup or observer failure cannot defer the latter.
func discoveryHeaderViabilitySourceExit(err error) bool {
	for depth := 0; err != nil && depth < 32; depth++ {
		if receipt, ok := err.(*discoveryCapturedCommandError); ok {
			exit, ok := receipt.cause.(*exec.ExitError)
			return ok && exit.ExitCode() == 1
		}
		switch wrapped := err.(type) {
		case interface{ Unwrap() []error }:
			children := wrapped.Unwrap()
			if len(children) != 1 {
				return false
			}
			err = children[0]
		case interface{ Unwrap() error }:
			err = wrapped.Unwrap()
		default:
			return false
		}
	}
	return false
}

func (cache *discoveryHeaderViabilityCache) remove(key string) {
	if value, found := cache.entries[key]; found {
		cache.bytes -= len(key) + len(value)
		delete(cache.entries, key)
	}
}
