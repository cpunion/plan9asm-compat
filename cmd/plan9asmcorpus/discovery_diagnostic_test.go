package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const discoveryTestHTTP2GoAway = `http2: server sent GOAWAY and closed the connection; ` +
	`LastStreamID=3, ErrCode=NO_ERROR, debug="server_shutting_down"`

func TestDiscoveryMixedAssemblerAndInfrastructureDiagnostics(t *testing.T) {
	const source = "pkg/file.s:12: unexpected EOF\nasm: assembly of pkg/file.s failed"
	for _, diagnostic := range []struct {
		name      string
		message   string
		retryable bool
	}{
		{"proxy", "reading https://example.com/pkg: 503 Service Unavailable", true},
		{"network EOF", "Get https://example.com/pkg: unexpected EOF", true},
		{
			"Git HTTPS disconnect",
			"fatal: unable to access 'https://github.com/example/repo/': " +
				"LibreSSL SSL_connect: SSL_ERROR_SYSCALL in connection to github.com:443",
			true,
		},
		{"checksum HTTP2 stream", "reading https://sum.golang.org/tile/8/0/x218/247: stream error: stream ID 13; INTERNAL_ERROR; received from peer", true},
		{"module ZIP HTTP2 stream", "read \"https://proxy.golang.org/example.com/pkg/@v/v1.0.0.zip\": stream error: stream ID 5; INTERNAL_ERROR; received from peer", true},
		{
			"module HTTP2 GOAWAY",
			`read "https://proxy.golang.org/example.com/pkg/@v/v1.0.0.mod": ` + discoveryTestHTTP2GoAway,
			true,
		},
		{"assembly URL EOF", "Get https://example.com/file.s:12: unexpected EOF", true},
		{"disk", "write object.o: no space left on device", false},
		{"killed", "go build: signal: killed", false},
		{"output pipe deadline", "exec: WaitDelay expired before I/O complete", false},
		{"descendant cleanup", "terminate discovery command group: operation not permitted", false},
		{"toolchain", "compile: version does not match go tool version", false},
		{"checksum", "verifying example.com/pkg: checksum mismatch\nSECURITY ERROR", false},
	} {
		t.Run(diagnostic.name, func(t *testing.T) {
			for _, combined := range []string{
				source + "\n" + diagnostic.message,
				diagnostic.message + "\n" + source,
			} {
				if !isDiscoveryGoBuildInfrastructureFailure(combined) {
					t.Fatalf("mixed failure was classified as source N/A: %s", combined)
				}
				if got := isDiscoveryRetryableNetworkFailure(combined); got != diagnostic.retryable {
					t.Fatalf("retryable=%v, want %v: %s", got, diagnostic.retryable, combined)
				}
			}
		})
	}
}

func TestDiscoveryGoToolCrashesCannotBecomeSourceNA(t *testing.T) {
	for _, diagnostic := range []string{
		"go tool compile: signal: segmentation fault",
		"go tool asm: signal: bus error",
		"go tool link: signal: aborted",
		"go tool vet: SIGILL: illegal instruction",
		"SIGSEGV: segmentation violation\nruntime.getGCMask",
		"panic: unexpected compiler state\nruntime.gopanic",
		"compile: internal compiler error: invalid operand",
	} {
		t.Run(strings.Split(diagnostic, "\n")[0], func(t *testing.T) {
			if !isDiscoveryGoBuildInfrastructureFailure(diagnostic) || isDiscoveryRetryableNetworkFailure(diagnostic) {
				t.Fatalf("tool crash became source N/A or a network retry: %q", diagnostic)
			}
			attempts := 0
			results, err := runDiscoveryPackageChecks([]discoveryPackageGroup{
				{Pattern: "example.com/first"}, {Pattern: "example.com/second"},
			}, func([]string) error {
				attempts++
				return errors.New(diagnostic)
			})
			if err == nil || results != nil || attempts != 1 {
				t.Fatalf("crashed batch was retried/classified per source: results=%v attempts=%d error=%v", results, attempts, err)
			}
		})
	}
}

func TestDiscoveryAssemblerEOFRequiresMatchingSourceDiagnostic(t *testing.T) {
	for _, filename := range []string{"pkg/file.s", "pkg with spaces/file.s", `C:\source\file.s`} {
		for _, newline := range []string{"\n", "\r\n"} {
			for _, position := range []string{"12", "12:3"} {
				diagnostic := filename + ":" + position + ": unexpected EOF" + newline +
					"asm: assembly of " + filename + " failed" + newline
				if isDiscoveryGoBuildInfrastructureFailure(diagnostic) || isDiscoveryRetryableNetworkFailure(diagnostic) {
					t.Fatalf("deterministic assembler EOF must remain source N/A: %q", diagnostic)
				}
			}
		}
	}
	for _, diagnostic := range []string{
		"pkg/file.s:12: unexpected EOF\nasm: assembly of other.s failed",
		"pkg/File.s:12: unexpected EOF\nasm: assembly of pkg/file.s failed",
		"pkg/file.s:invalid: unexpected EOF\nasm: assembly of pkg/file.s failed",
		"pkg/file.s:12:3:4: unexpected EOF\nasm: assembly of pkg/file.s failed",
		"pkg/file.s:12: unexpected EOF while fetching dependency\nasm: assembly of pkg/file.s failed",
		"pkg/file.s:12: unexpected EOF",
	} {
		if !isDiscoveryGoBuildInfrastructureFailure(diagnostic) {
			t.Fatalf("ambiguous EOF diagnostic was treated as source rejection: %q", diagnostic)
		}
	}
}

func TestDiscoveryHTTP2StreamRetryRequiresHTTPRead(t *testing.T) {
	for _, diagnostic := range []string{
		"pkg/file.s:12: stream error: stream ID 13; INTERNAL_ERROR; received from peer",
		"go build: stream error: stream ID 13; INTERNAL_ERROR; received from peer",
	} {
		if isDiscoveryRetryableNetworkFailure(diagnostic) {
			t.Fatalf("non-HTTP stream error was retried: %s", diagnostic)
		}
	}
}

func TestDiscoveryHTTP2GoAwayRetryRequiresHTTPReadAndShutdown(t *testing.T) {
	for _, diagnostic := range []string{
		`read "https://proxy.golang.org/example.com/pkg/@v/v1.0.0.mod": ` + discoveryTestHTTP2GoAway,
		`reading https://sum.golang.org/tile/8/0/x218/247: ` + discoveryTestHTTP2GoAway,
	} {
		if !isDiscoveryGoBuildInfrastructureFailure(diagnostic) || !isDiscoveryRetryableNetworkFailure(diagnostic) {
			t.Errorf("HTTP/2 server shutdown must be retried: %s", diagnostic)
		}
	}
	for _, diagnostic := range []string{
		"go build: " + discoveryTestHTTP2GoAway,
		"pkg/file.s:12: " + discoveryTestHTTP2GoAway,
		`read "file:///source.s": ` + discoveryTestHTTP2GoAway,
		`read "https://proxy.golang.org/pkg.mod": ` +
			`http2: server sent GOAWAY and closed the connection; ` +
			`LastStreamID=3, ErrCode=PROTOCOL_ERROR, debug="protocol_error"`,
	} {
		if isDiscoveryRetryableNetworkFailure(diagnostic) {
			t.Errorf("non-shutdown source/tool diagnostic was retried: %s", diagnostic)
		}
	}
	if isDiscoveryRetryableNetworkFailure("checksum mismatch\n" +
		`read "https://proxy.golang.org/pkg.mod": ` + discoveryTestHTTP2GoAway) {
		t.Fatal("checksum mismatch must not be hidden by an HTTP/2 shutdown")
	}
}

func TestDiscoveryRetryHTTP2GoAway(t *testing.T) {
	const diagnostic = `read "https://proxy.golang.org/example.com/pkg/@v/v1.0.0.mod": ` +
		discoveryTestHTTP2GoAway
	attempts := 0
	err := retryDiscoveryGoNetwork(context.Background(), []time.Duration{0}, func() error {
		attempts++
		if attempts == 1 {
			return errors.New(diagnostic)
		}
		return nil
	})
	if err != nil || attempts != 2 {
		t.Fatalf("GOAWAY retry: attempts=%d error=%v, want two attempts and success", attempts, err)
	}
}

func TestDiscoveryFatalFailurePrecedesTransientNetworkDiagnostic(t *testing.T) {
	for _, fatal := range []string{
		"verifying example.com/pkg: checksum mismatch\nSECURITY ERROR",
		"write object.o: no space left on device",
		"go build: signal: killed",
		"compile: version does not match go tool version",
		"go build: captured output exceeds 8388608 bytes",
		"go build: context deadline exceeded",
		"go build: context canceled",
		"exec: go: executable file not found in PATH",
		"fork/exec go: exec format error",
		"fork/exec go: permission denied",
		"fork/exec compile: resource temporarily unavailable",
		"fatal error: runtime: out of memory",
	} {
		if !isDiscoveryGoBuildInfrastructureFailure(fatal) {
			t.Errorf("infrastructure error was classified as source N/A: %s", fatal)
		}
		diagnostic := fatal + "\nreading https://example.com/pkg: 503 Service Unavailable"
		if !isDiscoveryGoBuildInfrastructureFailure(diagnostic) {
			t.Fatalf("fatal error was classified as source N/A: %s", diagnostic)
		}
		if isDiscoveryRetryableNetworkFailure(diagnostic) {
			t.Errorf("fatal error was retried because another dependency had a network failure: %s", diagnostic)
		}
	}
}

func TestDiscoveryChecksumFailureCannotBecomeSourceNotApplicable(t *testing.T) {
	diagnostic := "verifying example.com/pkg: checksum mismatch\nSECURITY ERROR"
	if !isDiscoveryGoBuildInfrastructureFailure(diagnostic) {
		t.Fatal("checksum mismatch was classified as source incompatibility")
	}
	if isDiscoveryRetryableNetworkFailure(diagnostic) {
		t.Fatal("checksum mismatch must not be retried as a transient network error")
	}
}

func TestDiscoveryGitHTTPSDisconnectClassification(t *testing.T) {
	for _, cause := range []string{
		"LibreSSL SSL_connect: SSL_ERROR_SYSCALL in connection to github.com:443",
		"OpenSSL SSL_connect: SSL_ERROR_SYSCALL in connection to github.com:443",
		"LibreSSL SSL_read: SSL_ERROR_SYSCALL, errno 0",
		"OpenSSL SSL_read: SSL_ERROR_SYSCALL, errno 0",
		"GnuTLS recv error (-110): The TLS connection was non-properly terminated.",
		"GnuTLS handshake error (-110): The TLS connection was non-properly terminated.",
	} {
		diagnostic := "fatal: unable to access 'https://github.com/example/repo/': " + cause
		if !isDiscoveryGoBuildInfrastructureFailure(diagnostic) || !isDiscoveryRetryableNetworkFailure(diagnostic) {
			t.Errorf("Git TLS transport failure was not retryable infrastructure: %s", diagnostic)
		}
	}
	for _, test := range []struct {
		diagnostic     string
		infrastructure bool
	}{
		{"pkg/file.s:12: SSL_ERROR_SYSCALL", false},
		{"go build: LibreSSL SSL_connect: SSL_ERROR_SYSCALL", false},
		{"fatal: unable to access 'file:///source.s': SSL_ERROR_SYSCALL", false},
		{"pkg/file.s:12: fatal: unable to access 'https://github.com/example/repo/': LibreSSL SSL_connect: SSL_ERROR_SYSCALL", false},
		{"fatal: unable to access 'https://github.com/example/repo/': server certificate verification failed", true},
		{"fatal: unable to access 'https://github.com/example/repo/': SSL certificate problem: certificate has expired", true},
		{"fatal: unable to access 'https://github.com/example/repo/': SSL_ERROR_SSL", true},
		{"fatal: unable to access 'https://github.com/example/repo/': The requested URL returned error: 404", true},
	} {
		if got := isDiscoveryGoBuildInfrastructureFailure(test.diagnostic); got != test.infrastructure {
			t.Errorf("infrastructure=%v, want %v: %s", got, test.infrastructure, test.diagnostic)
		}
		if isDiscoveryRetryableNetworkFailure(test.diagnostic) {
			t.Errorf("non-transport or certificate failure was retried: %s", test.diagnostic)
		}
	}
	for _, fatal := range []string{
		"checksum mismatch\nSECURITY ERROR",
		"write object: no space left on device",
		"SSL certificate problem: unable to get local issuer certificate",
		"server certificate verification failed",
	} {
		diagnostic := fatal + "\nfatal: unable to access 'https://github.com/example/repo/': " +
			"LibreSSL SSL_connect: SSL_ERROR_SYSCALL in connection to github.com:443"
		if !isDiscoveryGoBuildInfrastructureFailure(diagnostic) || isDiscoveryRetryableNetworkFailure(diagnostic) {
			t.Errorf("fatal integrity/resource/certificate failure lost precedence: %s", diagnostic)
		}
	}
}

func TestDiscoveryRetryMixedAssemblerNetworkEOF(t *testing.T) {
	const source = "pkg/file.s:12: unexpected EOF\nasm: assembly of pkg/file.s failed"
	attempts := 0
	err := retryDiscoveryGoNetwork(context.Background(), []time.Duration{0}, func() error {
		attempts++
		if attempts == 1 {
			return errors.New(source + "\nGet https://example.com/pkg: unexpected EOF")
		}
		return errors.New(source)
	})
	if attempts != 2 || err == nil || !strings.Contains(err.Error(), source) {
		t.Fatalf("attempts=%d error=%v, want retry followed by source rejection", attempts, err)
	}
}

func TestDiscoveryActualAssemblerEOFRemainsSourceRejection(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "go.mod"), "module example.com/truncatedasm\n\ngo 1.20\n")
	writeTestFile(t, filepath.Join(dir, "decl.go"), "package truncatedasm\n\nfunc f()\n")
	// Deliberately omit the final newline to exercise the real Go diagnostic.
	writeTestFile(t, filepath.Join(dir, "decl_amd64.s"), "TEXT ·f(SB), $0-0\nRET")
	env := replaceEnv(os.Environ(), map[string]string{"GOFLAGS": "-mod=mod", "GOWORK": "off"})
	err := runDiscoveryGoBuild(context.Background(), dir, env, "linux/amd64", nil, "example.com/truncatedasm")
	if err == nil || !strings.Contains(err.Error(), "unexpected EOF") {
		t.Fatalf("expected an actual assembler EOF, got %v", err)
	}
	if isDiscoveryInfrastructureFailure(err) || isDiscoveryRetryableNetworkFailure(err.Error()) {
		t.Fatalf("actual Go source rejection was classified as infrastructure failure: %v", err)
	}
}

func TestDiscoveryProgressRejectsInfrastructureSourceNotApplicable(t *testing.T) {
	for _, status := range []string{discoveryStatusPassed, discoveryStatusNotApplicable} {
		t.Run(status, func(t *testing.T) {
			ledger, reports, source := writeDiscoveryReportFixture(t)
			files, err := discoveryCorpusReportFiles(reports)
			if err != nil {
				t.Fatal(err)
			}
			for _, filename := range files {
				report, err := readDiscoveryCorpusReport(filename)
				if err != nil {
					t.Fatal(err)
				}
				if len(report.Results) == 0 {
					continue
				}
				result := &report.Results[0]
				result.SourceNotApplicableItems = []discoverySourceNotApplicableItem{{
					AsmFiles: result.DiscoveredAsmFiles,
					Targets:  []string{"linux/arm64"},
					Kind:     discoverySourceNotApplicableGoBuild,
					Reason: "pkg/file.s:12: unexpected EOF\nasm: assembly of pkg/file.s failed\n" +
						"reading https://example.com/pkg: 503 Service Unavailable",
				}}
				if status == discoveryStatusNotApplicable {
					result.Status = status
					result.NotApplicableReason = "current Go package rejected"
					report.Passed--
					report.NotApplicable++
					report.Translations -= result.Translations
					result.Translations = 0
				}
				if err := writeDiscoveryCorpusReport(filename, report); err != nil {
					t.Fatal(err)
				}
				targets := []string{"linux/amd64", "linux/arm64"}
				if _, err := collectDiscoveryProgress(ledger, reports, targets, source, 2); err == nil ||
					!strings.Contains(err.Error(), "infrastructure failure") {
					t.Fatalf("progress must reject infrastructure N/A before ledger publication: %v", err)
				}
				if err := verifyDiscoveryCorpusReports(ledger, reports, targets, source); err == nil ||
					!strings.Contains(err.Error(), "infrastructure failure") {
					t.Fatalf("final gate accepted infrastructure N/A: %v", err)
				}
				return
			}
			t.Fatal("fixture contains no candidate")
		})
	}
}

func TestDiscoveryHTTPResponseEOFIsRetryable(t *testing.T) {
	for _, method := range []string{
		http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodDelete, http.MethodPatch, http.MethodOptions,
		http.MethodConnect, http.MethodTrace,
	} {
		for _, scheme := range []string{"http", "https"} {
			failure := &url.Error{Op: method, URL: scheme + "://example.com/sumdb/supported", Err: io.EOF}
			for _, diagnostic := range []string{
				failure.Error(),
				"verifying go.mod: initializing sumdb.Client: checking tree#1: " + failure.Error(),
				failure.Error() + "\r\n",
			} {
				if !isDiscoveryGoBuildInfrastructureFailure(diagnostic) || !isDiscoveryRetryableNetworkFailure(diagnostic) {
					t.Errorf("HTTP response EOF must be an infrastructure retry: %s", diagnostic)
				}
			}
			terminal := "checksum mismatch\n" + failure.Error()
			if isDiscoveryRetryableNetworkFailure(terminal) {
				t.Errorf("HTTP EOF must not override checksum failure: %s", terminal)
			}
		}
	}
	for _, diagnostic := range []string{
		"source.s:12: EOF",
		"EOF",
		`Get "file:///source.s": EOF`,
		`Get "https://example.com/module": EOF in source`,
	} {
		if isDiscoveryRetryableNetworkFailure(diagnostic) {
			t.Errorf("non-HTTP EOF was retried as a network failure: %s", diagnostic)
		}
	}
}
