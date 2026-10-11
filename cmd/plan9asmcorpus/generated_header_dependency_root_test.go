package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/mod/sumdb/dirhash"
)

func TestOrdinaryDependencyProducerRetainsActualRootAlias(t *testing.T) {
	for _, axis := range []string{"canonical", "ancestor alias", "repointed", "cancelled"} {
		t.Run(axis, func(t *testing.T) {
			candidate := discoveryCandidate{Module: "example.invalid/root-owner", Version: "v1.0.0", AsmFiles: []string{"probe.s"}}
			files := map[string]string{
				"go.mod":   "module " + candidate.Module + "\ngo 1.20\n",
				"probe.go": "package owner\nfunc Probe()\n", "probe.s": "TEXT ·Probe(SB),4,$0-0\nRET\n",
				"asset.bin": "original owner bytes\n",
			}
			download := fixtureProfileModuleDownload(t, candidate, files)
			var err error
			download.Sum, err = dirhash.HashZip(download.Zip, dirhash.Hash1)
			if err != nil {
				t.Fatal(err)
			}
			download.GoModSum, err = dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) {
				return os.Open(download.GoMod)
			})
			if err != nil {
				t.Fatal(err)
			}
			root, err := filepath.EvalSymlinks(download.Dir)
			if err != nil {
				t.Fatal(err)
			}
			var inventory gotoolprofile.SourceInventory
			if err := gotoolprofile.CaptureSourceDirectory(context.Background(), &inventory, root, root, false); err != nil {
				t.Fatal(err)
			}
			plan := &discoveryOrdinarySelectionPlan{Module: candidate.Module, Version: candidate.Version, ModuleSum: download.Sum}
			plan.ZipSHA256, err = discoveryFeatureFileSHA256(download.Zip)
			if err != nil {
				t.Fatal(err)
			}
			alias := filepath.Join(t.TempDir(), "ancestor")
			if err := os.Symlink(filepath.Dir(root), alias); err != nil {
				t.Fatal(err)
			}
			download.Dir = root
			if axis != "canonical" {
				download.Dir = filepath.Join(alias, filepath.Base(root))
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			proof := &gotoolprofile.OrdinaryDependencyProof{Protocol: gotoolprofile.OrdinaryDependencyProtocol, Candidate: inventory}
			if err := verifyDiscoveryOrdinaryDependencies(ctx, plan, download, proof, t.TempDir(), nil); err != nil {
				t.Fatalf("original candidate ZIP through its actual root spelling: %v", err)
			}
			if err := verifyDiscoveryOrdinaryDependencySnapshots(plan); err != nil || len(plan.ordinaryDependencyGuards) != 1 {
				t.Fatalf("unchanged original owner: %v", err)
			}
			if axis == "repointed" {
				parent := t.TempDir()
				copyRoot := filepath.Join(parent, filepath.Base(root))
				if err := os.MkdirAll(copyRoot, 0700); err != nil {
					t.Fatal(err)
				}
				for name, data := range files {
					writeTestFile(t, filepath.Join(copyRoot, name), data)
				}
				if err := os.Remove(alias); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(parent, alias); err != nil {
					t.Fatal(err)
				}
			} else if axis == "cancelled" {
				cancel()
			} else {
				return
			}
			if err := verifyDiscoveryOrdinaryDependencySnapshots(plan); err == nil {
				t.Fatal("changed actual root identity or closed context acquired ordinary source authority")
			}
		})
	}
}
