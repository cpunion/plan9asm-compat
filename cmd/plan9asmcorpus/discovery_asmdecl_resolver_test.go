package main

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDiscoveryAsmDeclDirectActualModuleResolverNotices(t *testing.T) {
	const dependency = "example.invalid/direct-resolver-dep"
	const version = "v1.0.0"
	const goMod = "module " + dependency + "\n\ngo 1.20\n"
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	for _, file := range []struct{ name, contents string }{
		{"go.mod", goMod},
		{"dep/decl.go", "package dep\nconst Value = 17\n"},
	} {
		entry, err := writer.Create(dependency + "@" + version + "/" + file.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(file.contents)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/" + dependency + "/@v/list":
			fmt.Fprintln(w, version)
		case "/" + dependency + "/@latest", "/" + dependency + "/@v/" + version + ".info":
			fmt.Fprintf(w, `{"Version":%q,"Time":"2026-01-01T00:00:00Z"}`, version)
		case "/" + dependency + "/@v/" + version + ".mod":
			fmt.Fprint(w, goMod)
		case "/" + dependency + "/@v/" + version + ".zip":
			_, _ = w.Write(archive.Bytes())
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	root := discoveryAsmDeclRetryPhysicalTemp(t)
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.invalid/direct-resolver-main\n\ngo 1.20\n")
	writeTestFile(t, filepath.Join(root, "decl.go"), "package resolver\nimport \""+dependency+"/dep\"\nvar _ = dep.Value\nfunc Value() uint64\n")
	writeTestFile(t, filepath.Join(root, "decl_amd64.s"), "TEXT ·Value(SB),4,$0-8\nMOVQ $17,ret+0(FP)\nRET\n")
	env := replaceEnv(discoveryAsmDeclDirectFixtureEnv(t, root), map[string]string{
		"GOPROXY": server.URL, "GOSUMDB": "off", "GONOPROXY": "none", "GONOSUMDB": "none",
		"GOMODCACHE": t.TempDir(),
	})
	// Go extracts module directories read-only. Clean this exact owned cache
	// with the SDK tool before TempDir's directory cleanup runs.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if _, err := runCapturedCommandOutput(ctx, root, env, "go", "clean", "-modcache"); err != nil {
			t.Errorf("clean owned resolver fixture module cache: %v", err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := runDiscoveryAsmDeclDirect(ctx, root, env, nil, []string{"."}, ""); err != nil {
		t.Fatalf("actual successful module resolution could not reach complete official asmdecl analysis: %v", err)
	}
}

func TestDiscoveryAsmDeclDirectModuleResolverNoticeGrammar(t *testing.T) {
	const found = "go: found example.invalid/dep/pkg in example.invalid/dep v1.2.3\n"
	const finding = "go: finding module for package example.invalid/dep/pkg\n"
	const download = "go: downloading example.invalid/dep v1.2.3\n"
	for name, text := range map[string]string{
		"finding": finding, "found": found, "complete sequence": finding + download + found,
		"major suffix": "go: found example.invalid/dep/v2/pkg in example.invalid/dep/v2 v2.0.1\n",
	} {
		t.Run(name, func(t *testing.T) {
			if err := directAsmDeclValidateSuccessfulStderr([]string{"list", "-json", "-mod=mod"}, text); err != nil {
				t.Fatalf("exact successful cmd/go resolver grammar refused: %v", err)
			}
		})
	}
	for name, text := range map[string]string{
		"foreign package":      "go: found example.invalid/other/pkg in example.invalid/dep v1.2.3\n",
		"invalid path":         "go: finding module for package ../dep\n",
		"invalid version":      "go: found example.invalid/dep/pkg in example.invalid/dep version\n",
		"wrong major":          "go: found example.invalid/dep/v2/pkg in example.invalid/dep/v2 v1.2.3\n",
		"extra whitespace":     strings.Replace(found, "found ", "found  ", 1),
		"extra field":          strings.TrimSpace(found) + " extra\n",
		"unknown trailer":      found + "unknown successful warning\n",
		"toolchain resolution": "go: found golang.org/toolchain in golang.org/toolchain v0.0.1-go1.27.1.linux-amd64\n",
		"toolchain search":     "go: finding module for package golang.org/toolchain\n",
	} {
		t.Run(name, func(t *testing.T) {
			if err := directAsmDeclValidateSuccessfulStderr([]string{"list", "-json", "-mod=mod"}, text); err == nil {
				t.Fatal("malformed, unknown or different-identity notice was accepted")
			}
		})
	}
	for _, command := range []string{"env", "version", "tool", "vet"} {
		if err := directAsmDeclValidateSuccessfulStderr([]string{command}, finding+found); err == nil {
			t.Fatalf("%s borrowed the cmd/go list resolver grammar", command)
		}
	}
}
