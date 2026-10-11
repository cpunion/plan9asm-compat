package main

import (
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

type discoveryCPPRegistration struct {
	Protocol           string            `json:"protocol"`
	GoVersion          string            `json:"go_version"`
	ToolSourceSHA256   map[string]string `json:"tool_source_sha256"`
	RegistrationSHA256 map[string]string `json:"registration_ast_sha256"`
}

// Audit the complete directive dispatcher, macro/include semantics and lexical
// namespace, not guessed identifiers. The compact condition parser is a
// deliberately bounded subset: unknown directive-generating macro bodies fail.
func captureDiscoveryCPPRegistration(root, version string) (*discoveryCPPRegistration, error) {
	minor, err := discoveryGoMinor(version)
	if !filepath.IsAbs(root) || err != nil || minor < 20 || minor > 27 {
		return nil, fmt.Errorf("CPP registration requires an audited actual Go source/version")
	}
	versionBytes, err := os.ReadFile(filepath.Join(root, "VERSION"))
	if err != nil || strings.TrimSpace(strings.Split(string(versionBytes), "\n")[0]) != version {
		return nil, fmt.Errorf("CPP registration source VERSION differs from actual driver")
	}
	proof := &discoveryCPPRegistration{Protocol: "go_assembler_cpp_registration_v1", GoVersion: version,
		ToolSourceSHA256: map[string]string{"VERSION": discoveryFeatureBytesSHA256(versionBytes)}, RegistrationSHA256: make(map[string]string)}
	for _, file := range []string{"input", "tokenizer"} {
		name := "src/cmd/asm/internal/lex/" + file + ".go"
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			return nil, err
		}
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, name, data, 0)
		if err != nil || parsed.Name.Name != "lex" {
			return nil, fmt.Errorf("invalid actual Go CPP registration source %s", name)
		}
		fingerprint, err := discoveryAssemblerASTSHA(fset, parsed)
		if err != nil || fingerprint != discoveryCPPRegistrationFingerprint(minor, file) {
			return nil, fmt.Errorf("unrecognized actual Go CPP registration: %s", name)
		}
		proof.ToolSourceSHA256[name] = discoveryFeatureBytesSHA256(data)
		proof.RegistrationSHA256[file] = fingerprint
	}
	return proof, nil
}

func validateDiscoveryCPPRegistration(proof *discoveryCPPRegistration, version string) error {
	minor, err := discoveryGoMinor(version)
	if proof == nil || proof.Protocol != "go_assembler_cpp_registration_v1" || proof.GoVersion != version || err != nil || minor < 20 || minor > 27 ||
		len(proof.ToolSourceSHA256) != 3 || len(proof.RegistrationSHA256) != 2 {
		return fmt.Errorf("missing complete actual Go CPP registration proof")
	}
	for _, file := range []string{"input", "tokenizer"} {
		if proof.RegistrationSHA256[file] != discoveryCPPRegistrationFingerprint(minor, file) || !discoverySHA256Pattern.MatchString(proof.ToolSourceSHA256["src/cmd/asm/internal/lex/"+file+".go"]) {
			return fmt.Errorf("unknown actual Go CPP registration/lexical namespace")
		}
	}
	if !discoverySHA256Pattern.MatchString(proof.ToolSourceSHA256["VERSION"]) {
		return fmt.Errorf("CPP registration has no actual source VERSION identity")
	}
	return nil
}

func discoveryCPPRegistrationFingerprint(minor int, file string) string {
	if minor < 20 || minor > 27 {
		return ""
	}
	if file == "tokenizer" {
		return "071b137542c369ddfbdc008f1c5866767d348362473305f93ee62e43bfd9c838"
	}
	if file != "input" {
		return ""
	}
	switch {
	case minor <= 21:
		return "a385559ed2aaa95e69494f1a7a8d84385dab708b76788b08d426c46c254899c9"
	case minor <= 23:
		return "1e7f99798bd295847ba0be16c4e7da7ccfda1415370603ffd7f7d56bd47a902f"
	case minor <= 25:
		return "88d77e6f5cde93c9f720ce13fdb8ff455632680526a98e69177e287609d3c44e"
	default:
		return "8ccf855e2eadef60bdc25a47b8d4d5f626262a10f7fe7dce55f8e696acf73ce0"
	}
}
