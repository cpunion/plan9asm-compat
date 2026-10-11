package main

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDiscoveryDownloadRetriesTransientProxyFailure(t *testing.T) {
	const module = "example.com/discovery-retry"
	const version = "v1.0.0"
	const goMod = "module " + module + "\n\ngo 1.20\n"
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	entry, err := writer.Create(module + "@" + version + "/go.mod")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte(goMod)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		status   int
		failures int32
		wantRuns int32
		wantErr  bool
	}{
		{"recover", http.StatusServiceUnavailable, 2, 3, false},
		{"bounded-retries", http.StatusServiceUnavailable, 9, 3, true},
		{"permanent-not-found", http.StatusNotFound, 9, 1, true},
		{"closed-response-recovers", 0, 2, 3, false},
		{"closed-response-bounded", 0, 9, 3, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/" + module + "/@v/" + version + ".info":
					if requests.Add(1) <= test.failures {
						if test.status == 0 {
							conn, _, err := w.(http.Hijacker).Hijack()
							if err != nil {
								t.Errorf("hijack proxy response: %v", err)
								return
							}
							conn.Close()
							return
						}
						http.Error(w, http.StatusText(test.status), test.status)
						return
					}
					fmt.Fprintf(w, `{"Version":%q,"Time":"2026-01-01T00:00:00Z"}`, version)
				case "/" + module + "/@v/" + version + ".mod":
					fmt.Fprint(w, goMod)
				case "/" + module + "/@v/" + version + ".zip":
					_, _ = w.Write(archive.Bytes())
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			t.Setenv("GOPROXY", server.URL)
			t.Setenv("GOSUMDB", "off") // Only this local, synthetic proxy fixture.
			t.Setenv("GONOPROXY", "none")
			t.Setenv("GOMODCACHE", t.TempDir())
			work := filepath.Join(t.TempDir(), "candidate")
			_, _, _, err := runDiscoveryCandidate(
				discoveryCorpusConfig{CandidateTimeout: 30 * time.Second},
				discoveryCandidate{Module: module, Version: version}, work,
			)
			if (err != nil) != test.wantErr || requests.Load() != test.wantRuns {
				t.Fatalf("download requests=%d, error=%v; want requests=%d, error=%v", requests.Load(), err, test.wantRuns, test.wantErr)
			}
			wantDiagnostic := http.StatusText(test.status)
			if test.status == 0 {
				wantDiagnostic = ": EOF"
			}
			if err != nil && !strings.Contains(err.Error(), wantDiagnostic) {
				t.Fatalf("lost final proxy diagnostic: %v", err)
			}
			if _, err := os.Stat(work); !os.IsNotExist(err) {
				t.Fatalf("download attempt leaked its candidate workspace: %v", err)
			}
		})
	}
}

func TestDiscoveryNetworkRetryKeepsDeadlineAndDeterministicFailures(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	err := retryDiscoveryGoNetwork(ctx, nil, func() error {
		calls++
		return nil
	})
	if !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatalf("canceled download started: calls=%d error=%v", calls, err)
	}

	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	transient := errors.New("proxy: TLS handshake timeout")
	err = retryDiscoveryGoNetwork(ctx, []time.Duration{time.Hour}, func() error {
		cancel()
		return transient
	})
	if !errors.Is(err, context.Canceled) || !errors.Is(err, transient) {
		t.Fatalf("retry lost cancellation or network diagnostic: %v", err)
	}

	for _, diagnostic := range []string{
		"checksum mismatch: SECURITY ERROR",
		"compile: version does not match go tool version",
		"write object: no space left on device",
		"file.s:2: unexpected EOF\nasm: assembly of file.s failed",
	} {
		calls = 0
		failure := errors.New(diagnostic)
		err := retryDiscoveryGoNetwork(context.Background(), []time.Duration{0, 0}, func() error {
			calls++
			return failure
		})
		if !errors.Is(err, failure) || calls != 1 {
			t.Fatalf("retried deterministic failure: calls=%d error=%v", calls, err)
		}
	}
}

func TestDiscoveryNetworkRetriesHTTP2StreamError(t *testing.T) {
	const diagnostic = "reading https://sum.golang.org/tile/8/0/x218/247: stream error: stream ID 13; INTERNAL_ERROR; received from peer"
	attempts := 0
	err := retryDiscoveryGoNetwork(context.Background(), []time.Duration{0, 0}, func() error {
		attempts++
		if attempts < 3 {
			return errors.New(diagnostic)
		}
		return nil
	})
	if err != nil || attempts != 3 {
		t.Fatalf("HTTP/2 stream error did not recover after retry: attempts=%d error=%v", attempts, err)
	}
}

func TestDiscoveryNetworkRetriesGitHTTPSDisconnect(t *testing.T) {
	const diagnostic = "github.com/paxeer-network/pax-geth@v1.13.2: invalid version: " +
		"git ls-remote -q --end-of-options https://github.com/paxeer-network/pax-geth: exit status 128:\n" +
		"\tfatal: unable to access 'https://github.com/paxeer-network/pax-geth/': " +
		"LibreSSL SSL_connect: SSL_ERROR_SYSCALL in connection to github.com:443"
	attempts := 0
	err := retryDiscoveryGoNetwork(context.Background(), []time.Duration{0, 0}, func() error {
		attempts++
		if attempts < 3 {
			return errors.New(diagnostic)
		}
		return nil
	})
	if err != nil || attempts != 3 {
		t.Fatalf("Git HTTPS disconnect retry: attempts=%d error=%v, want three attempts and success", attempts, err)
	}

	attempts = 0
	err = retryDiscoveryGoNetwork(context.Background(), []time.Duration{0, 0}, func() error {
		attempts++
		return errors.New(diagnostic)
	})
	if err == nil || attempts != 3 || !strings.Contains(err.Error(), "SSL_ERROR_SYSCALL") {
		t.Fatalf("persistent Git HTTPS failure lost bound/diagnostic: attempts=%d error=%v", attempts, err)
	}
}
