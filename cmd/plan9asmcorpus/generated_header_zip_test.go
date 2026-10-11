package main

import (
	"archive/zip"
	"os"
	"testing"
)

func TestGeneratedHeaderImportedSourceGuardRetainsWholeExactZIPIdentity(t *testing.T) {
	for _, duplicate := range []bool{false, true} {
		name := "same-members-new-archive"
		if duplicate {
			name = "duplicate-member"
		}
		t.Run(name, func(t *testing.T) {
			candidate := discoveryCandidate{Module: "example.invalid/generated", Version: "v1.0.0", AsmFiles: []string{"probe.s"}}
			sources := map[string]string{
				"go.mod":                   "module example.invalid/generated\n\ngo 1.20\n",
				"decl.go":                  "package fixture\nfunc Probe()\n",
				"probe.s":                  "TEXT ·Probe(SB),$0-0\nRET\n",
				"internal/layout/value.go": "package layout\nconst Answer = 7\n",
			}
			download := fixtureProfileModuleDownload(t, candidate, sources)
			plan, err := captureOrdinarySelectionInputs(candidate, download.Dir, []string{"linux/amd64"})
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyOrdinarySelectionZIP(plan, download.Zip, candidate.Module, candidate.Version, ""); err != nil {
				t.Fatal(err)
			}
			file := "internal/layout/value.go"
			plan.GeneratedGoSources = map[string]string{file: discoveryFeatureBytesSHA256([]byte(sources[file]))}
			if err := verifyDiscoveryGeneratedGoSources(plan, download.Dir, download.Zip); err != nil {
				t.Fatal(err)
			}
			// Only a t.TempDir-owned fixture archive is rewritten. Selected Go
			// bytes and recorded hashes stay unchanged; the whole ZIP may not.
			archive, err := os.Create(download.Zip)
			if err != nil {
				t.Fatal(err)
			}
			writer := zip.NewWriter(archive)
			if err := writer.SetComment("changed after initial original-ZIP validation"); err != nil {
				t.Fatal(err)
			}
			for name, data := range sources {
				entry, err := writer.Create(candidate.Module + "@" + candidate.Version + "/" + name)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := entry.Write([]byte(data)); err != nil {
					t.Fatal(err)
				}
			}
			if duplicate {
				entry, err := writer.Create(candidate.Module + "@" + candidate.Version + "/" + file)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := entry.Write([]byte(sources[file])); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			if err := archive.Close(); err != nil {
				t.Fatal(err)
			}
			if err := verifyDiscoveryGeneratedGoSources(plan, download.Dir, download.Zip); err == nil {
				t.Fatal("unchanged selected imported Go bytes hid a changed/duplicate original archive")
			}
		})
	}
}
