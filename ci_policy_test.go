package compatibility

import (
	"os"
	"strings"
	"testing"
)

func TestCIDiscoveredCorpusRetainsAuthenticatedProxyFallback(t *testing.T) {
	data, err := os.ReadFile(".github/workflows/go-ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	const signedSumDB = "GOSUMDB: ${{ github.repository_owner == 'xgo-dev' && 'sum.golang.google.cn' || 'sum.golang.org https://sum.golang.org' }}"
	for _, name := range []string{"discovered_library_priority", "discovered_library_corpus"} {
		corpus, found := ciWorkflowJob(string(data), name)
		if !found {
			t.Fatalf("%s job not found", name)
		}
		if !strings.Contains(corpus, "GOPROXY: https://proxy.golang.org,https://goproxy.cn,direct") {
			t.Errorf("%s must try both public module caches before the origin", name)
		}
		if !strings.Contains(corpus, signedSumDB) {
			t.Errorf("%s must verify against an official signed checksum database", name)
		}
		for _, disabled := range []string{"GONOSUMDB:", "GOPRIVATE:", "GOSUMDB: off"} {
			if strings.Contains(corpus, disabled) {
				t.Errorf("%s must not bypass checksum authentication with %s", name, disabled)
			}
		}
	}
}

func TestCIRequiresVerifiedAssemblyLedger(t *testing.T) {
	data, err := os.ReadFile(".github/workflows/go-ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	build, found := ciWorkflowJob(string(data), "build")
	if !found {
		t.Fatal("build job not found")
	}
	if !strings.Contains(build, "-assembly-ledger-status testdata/discovery/assembly-ledger") ||
		!strings.Contains(build, "-require-verified-assembly-ledger") {
		t.Fatal("CI must require every discovered candidate to be passed or explicitly skipped")
	}
	script, err := os.ReadFile("scripts/verify-discovered-library-corpus.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(script), "-compare-assembly-ledger") {
		t.Fatal("CI must compare committed assembly outcomes with current corpus reports")
	}
}

func ciWorkflowJob(source, name string) (string, bool) {
	source = strings.ReplaceAll(source, "\r\n", "\n")
	_, job, found := strings.Cut(source, "\n  "+name+":\n")
	if !found {
		return "", false
	}
	lines := strings.Split(job, "\n")
	for index, line := range lines {
		if strings.HasPrefix(line, "  ") && len(line) > 2 && line[2] != ' ' && line[2] != '#' {
			return strings.Join(lines[:index], "\n"), true
		}
	}
	return job, true
}
