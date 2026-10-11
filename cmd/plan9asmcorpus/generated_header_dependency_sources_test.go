package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestOrdinaryDependencyProducerGuardRetainsIndependentSnapshot(t *testing.T) {
	for _, axis := range []string{"valid", "bytes", "directory", "projection", "cancelled", "next stage"} {
		t.Run(axis, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, filepath.Join(root, "source.go"), "package fixture\n")
			writeTestFile(t, filepath.Join(root, "asset.bin"), "original")
			var inventory gotoolprofile.SourceInventory
			if err := gotoolprofile.CaptureSourceDirectory(context.Background(), &inventory, root, root, false); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			plan := &discoveryOrdinarySelectionPlan{ordinaryDependencyContext: ctx}
			source := gotoolprofile.ModuleSourceSnapshot{Protocol: gotoolprofile.TestDependencyModuleProtocol, GoVersion: "go1.27.1",
				Sources: inventory.Sources, Headers: inventory.Headers, Directories: inventory.Directories}
			if err := retainDiscoveryOrdinaryDependencyGuard(plan, discoveryOrdinaryDependencyGuard{Context: ctx, Source: source, Root: root}); err != nil {
				t.Fatal(err)
			}
			if err := retainDiscoveryOrdinaryDependencyGuard(plan, discoveryOrdinaryDependencyGuard{Context: ctx, Source: source, Root: root}); err != nil || len(plan.ordinaryDependencyGuards) != 1 {
				t.Fatalf("identical complete source proofs must not duplicate live guard state: %v", err)
			}
			switch axis {
			case "bytes":
				writeTestFile(t, filepath.Join(root, "asset.bin"), "changed")
			case "directory":
				writeTestFile(t, filepath.Join(root, "new.bin"), "new")
			case "projection":
				source.Sources["asset.bin"] = strings.Repeat("f", 64)
			case "cancelled":
				cancel()
			case "next stage":
				cancel()
				plan.ordinaryDependencyContext = context.Background()
			}
			if axis == "bytes" || axis == "directory" || axis == "projection" || axis == "cancelled" {
				guard := discoveryOrdinaryDependencyGuard{Context: ctx, Source: source, Root: root}
				if err := retainDiscoveryOrdinaryDependencyGuard(plan, guard); err == nil {
					t.Fatal("retaining a repeated or changed projection bypassed live verification")
				}
				if len(plan.ordinaryDependencyGuards) != 1 {
					t.Fatal("failed source verification retained another guard")
				}
			}
			err = verifyDiscoveryOrdinaryDependencySnapshots(plan)
			valid := axis == "valid" || axis == "projection" || axis == "next stage"
			if valid && err != nil || !valid && err == nil {
				t.Fatalf("snapshot axis=%s: %v", axis, err)
			}
			if axis == "projection" {
				if err := os.WriteFile(filepath.Join(root, "asset.bin"), []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := verifyDiscoveryOrdinaryDependencySnapshots(plan); err == nil {
					t.Fatal("public projection rewrote live source identity")
				}
			}
		})
	}
}
