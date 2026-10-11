package main

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

// A guard belongs to one synchronous pre/post-object snapshot invocation.
// Its operations remain private so tests can count real byte-verification
// calls without replacing global functions or affecting concurrent candidates.
type discoveryTestSnapshotGuard struct {
	zipHash      func(string) (string, error)
	verifySource func(context.Context, gotoolprofile.TestModuleSource, string, string) error
	zipHashes    map[string]string
	verified     map[discoveryTestSnapshotLocation][]gotoolprofile.TestModuleSource
}

type discoveryTestSnapshotLocation struct {
	root, archive string
}

func newDiscoveryTestSnapshotGuard() *discoveryTestSnapshotGuard {
	return &discoveryTestSnapshotGuard{
		zipHash:      discoveryFeatureFileSHA256,
		verifySource: gotoolprofile.VerifyTestModuleSource,
		zipHashes:    make(map[string]string),
		verified:     make(map[discoveryTestSnapshotLocation][]gotoolprofile.TestModuleSource),
	}
}

func (guard *discoveryTestSnapshotGuard) snapshotZIPHash(archive string) (string, error) {
	if digest, found := guard.zipHashes[archive]; found {
		return digest, nil
	}
	digest, err := guard.zipHash(archive)
	if err == nil {
		guard.zipHashes[archive] = digest
	}
	return digest, err
}

func (guard *discoveryTestSnapshotGuard) verify(ctx context.Context, source gotoolprofile.TestModuleSource,
	capture *discoveryTestModuleCapture,
) error {
	if ctx == nil {
		return fmt.Errorf("test dependency source verification requires a live context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	current, err := discoveryTestModuleSnapshotWithZIPHash(capture, guard.snapshotZIPHash)
	if err != nil || !reflect.DeepEqual(source, current) {
		return fmt.Errorf("test dependency source-root inventory changed")
	}
	location := discoveryTestSnapshotLocation{root: capture.Root, archive: capture.Download.Zip}
	for _, prior := range guard.verified[location] {
		if !reflect.DeepEqual(prior, current) {
			continue
		}
		// Actual origin paths still belong to this proof. Only identical original
		// byte/member/header checks are shared; exports and every metadata copy
		// are separately rechecked by the caller even on this path.
		resolved, err := filepath.EvalSymlinks(capture.Root)
		if err != nil || resolved != capture.Root {
			return fmt.Errorf("test dependency source root is missing or redirected")
		}
		return nil
	}
	if err := guard.verifySource(ctx, source, capture.Root, capture.Download.Zip); err != nil {
		return fmt.Errorf("final test dependency source root %s: %w", source.ID(), err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// The snapshot creates fresh source/header/directory maps and entry slices.
	// Copy its sole pointer-backed metadata too, so later changes cannot mutate
	// an already verified cache identity. No JSON normalization or hash-based
	// equality weakens exact token, header-byte or nil/empty distinctions.
	if current.ProxyGoMod != nil {
		proxy := *current.ProxyGoMod
		if proxy.Inclusion != nil {
			proxy.Inclusion = append(make([]string, 0, len(proxy.Inclusion)), proxy.Inclusion...)
		}
		current.ProxyGoMod = &proxy
	}
	guard.verified[location] = append(guard.verified[location], current)
	return nil
}
