package compatibility

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestCITranslatorPinMatchesLibrary(t *testing.T) {
	data, err := os.ReadFile("translator.json")
	if err != nil {
		t.Fatal(err)
	}
	var pin struct{ Repository, Revision string }
	if err := json.Unmarshal(data, &pin); err != nil {
		t.Fatal(err)
	}
	if len(pin.Revision) != 40 {
		t.Fatal("translator must pin a complete revision")
	}
	module, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(module), "-"+pin.Revision[:12]+"\n") ||
		!strings.Contains(pin.Repository, "github.com/cpunion/plan9asm.git") {
		t.Fatal("translator checkout and library pins disagree")
	}
}

func TestIndependentRepositoryDoesNotCopyTranslator(t *testing.T) {
	for _, name := range []string{"translate.go", "amd64_ctx.go", "cmd/plan9asmll", "gotoolprofile", "internal/gotoolprofile", "testdata/coverage"} {
		if _, err := os.Stat(name); !os.IsNotExist(err) {
			t.Errorf("translator-owned path %s present or inaccessible: %v", name, err)
		}
	}
}
