package main

import (
	"os"

	"path/filepath"

	"testing"
)

func installGeneratedFixtureProxy(t *testing.T, candidate discoveryCandidate, download moduleDownloadInfo, goMod string) {
	t.Helper()
	proxy := t.TempDir()
	versions := filepath.Join(proxy, candidate.Module, "@v")
	if err := os.MkdirAll(versions, 0755); err != nil {
		t.Fatal(err)
	}
	archive, err := os.ReadFile(download.Zip)
	if err != nil {
		t.Fatal(err)
	}
	for file, data := range map[string][]byte{
		candidate.Version + ".mod":  []byte(goMod),
		candidate.Version + ".info": []byte(`{"Version":"` + candidate.Version + `","Time":"2026-10-01T00:00:00Z"}`),
		candidate.Version + ".zip":  archive,
	} {
		if err := os.WriteFile(filepath.Join(versions, file), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("GOPROXY", "file://"+proxy)
	t.Setenv("GOSUMDB", "off")
	t.Setenv("GOMODCACHE", filepath.Join(t.TempDir(), "modules"))
}
