package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/tlog"
)

type forbiddenChecksumTransport struct{ requests int }

func (transport *forbiddenChecksumTransport) RoundTrip(*http.Request) (*http.Response, error) {
	transport.requests++
	return nil, fmt.Errorf("checksum fixture forbids network requests")
}

func TestDiscoveryCandidateActualGoEnvOwnsSumDBCheckpoint(t *testing.T) {
	work, borrowed := t.TempDir(), t.TempDir()
	marker := filepath.Join(borrowed, "untouched-checkpoint")
	writeTestFile(t, marker, "original checkpoint remains unchanged")
	env := isolatedDiscoveryModuleEnvironment([]string{"GOPATH=" + borrowed, "GOTOOLCHAIN=local"}, work, "", "off")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	output, _, err := runDiscoveryMachineCommand(ctx, work, env, "go", "env", "-json", "GOPATH", "GOMODCACHE")
	if err != nil {
		t.Fatal(err)
	}
	var actual map[string]string
	if err := json.Unmarshal(output, &actual); err != nil || len(actual) != 2 ||
		actual["GOPATH"] != filepath.Join(work, "gopath") || actual["GOMODCACHE"] != filepath.Join(work, "module-cache") {
		t.Fatalf("actual Go retained shared SumDB/module cache ownership: %s: %v", output, err)
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "original checkpoint remains unchanged" {
		t.Fatal("borrowed checkpoint changed during Go environment observation")
	}
}

func TestDiscoveryChecksumReadonlyProxyAvoidsRepeatMetadataRequests(t *testing.T) {
	owned, shared := t.TempDir(), filepath.Join(t.TempDir(), "shared cache")
	proxy := (&url.URL{Scheme: "file", Path: filepath.ToSlash(shared)}).String()
	reader, err := newDiscoverySumDBReader(context.Background(), owned, proxy+",https://proxy.golang.org,direct")
	if err != nil {
		t.Fatal(err)
	}
	transport := new(forbiddenChecksumTransport)
	reader.Client = &http.Client{Transport: transport}
	tile := tlog.Tile{H: 8, L: 2, N: 3, W: 242}
	body := bytes.Repeat([]byte{0x5a}, tile.W*tlog.HashSize)
	filename := filepath.Join(shared, "sumdb", "sum.golang.org", filepath.FromSlash(tile.Path()))
	if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filename, string(body))
	before, err := os.Stat(filename)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := reader.ReadTiles([]tlog.Tile{tile})
	if err != nil || len(actual) != 1 || !bytes.Equal(actual[0], body) {
		t.Fatalf("cached exact signed-tree tile was unnecessarily refetched: %v", err)
	}
	lookup := []byte("untrusted cached lookup: authentication is still required\n")
	lookupName := "lookup/example.org/library@v1.0.0"
	lookupFile := filepath.Join(shared, "sumdb", "sum.golang.org", filepath.FromSlash(lookupName))
	if err := os.MkdirAll(filepath.Dir(lookupFile), 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, lookupFile, string(lookup))
	actualLookup, err := reader.Read(lookupName, 16<<10)
	if err != nil || !bytes.Equal(actualLookup, lookup) || transport.requests != 0 {
		t.Fatalf("readonly lookup caused a repeat request: requests=%d, error=%v", transport.requests, err)
	}
	reader.SaveTiles([]tlog.Tile{tile}, actual)
	after, err := os.Stat(filename)
	if err != nil || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("borrowed tile changed during a readonly verification")
	}
	if _, err := os.Stat(reader.Cache); !os.IsNotExist(err) {
		t.Fatalf("reader populated an owned cache instead of keeping fetched/cache bytes in memory: %v", err)
	}
}

func TestDiscoveryChecksumReadonlyCacheRetainsMerkleAuthentication(t *testing.T) {
	shared := t.TempDir()
	proxy := (&url.URL{Scheme: "file", Path: filepath.ToSlash(shared)}).String()
	reader, err := newDiscoverySumDBReader(context.Background(), t.TempDir(), proxy)
	if err != nil {
		t.Fatal(err)
	}
	transport := new(forbiddenChecksumTransport)
	reader.Client = &http.Client{Transport: transport}
	leaves := make([]tlog.Hash, 256)
	var data []byte
	for index := range leaves {
		leaves[index] = tlog.RecordHash([]byte(fmt.Sprintf("independent checksum leaf %d", index)))
		data = append(data, leaves[index][:]...)
	}
	level := append([]tlog.Hash(nil), leaves...)
	for len(level) > 1 {
		var parents []tlog.Hash
		for index := 0; index < len(level); index += 2 {
			parents = append(parents, tlog.NodeHash(level[index], level[index+1]))
		}
		level = parents
	}
	tree := tlog.Tree{N: 256, Hash: level[0]}
	tile := tlog.Tile{H: 8, L: 0, N: 0, W: 256}
	filename := filepath.Join(shared, "sumdb", "sum.golang.org", filepath.FromSlash(tile.Path()))
	if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filename, string(data))
	rootTile := tlog.Tile{H: 8, L: 1, N: 0, W: 1}
	rootFilename := filepath.Join(shared, "sumdb", "sum.golang.org", filepath.FromSlash(rootTile.Path()))
	if err := os.MkdirAll(filepath.Dir(rootFilename), 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, rootFilename, string(tree.Hash[:]))
	indexes := []int64{tlog.StoredHashIndex(0, 17), tlog.StoredHashIndex(0, 255)}
	actual, err := tlog.TileHashReader(tree, reader).ReadHashes(indexes)
	if err != nil || len(actual) != 2 || actual[0] != leaves[17] || actual[1] != leaves[255] {
		t.Fatalf("cached tile did not retain independent root authentication: %v", err)
	}
	data[0] ^= 1
	writeTestFile(t, filename, string(data))
	if _, err := tlog.TileHashReader(tree, reader).ReadHashes(indexes); err == nil {
		t.Fatal("same-sized corrupt cache bytes bypassed Merkle authentication")
	}
	if transport.requests != 0 {
		t.Fatal("cache authentication failure triggered a network repair")
	}
}

func TestDiscoveryChecksumReadonlyCacheDoesNotHideMalformedExactEntries(t *testing.T) {
	for _, contents := range [][]byte{nil, []byte("short"), bytes.Repeat([]byte{0xa5}, 257*tlog.HashSize)} {
		t.Run(fmt.Sprintf("size_%d", len(contents)), func(t *testing.T) {
			owned, shared := t.TempDir(), t.TempDir()
			proxy := (&url.URL{Scheme: "file", Path: filepath.ToSlash(shared)}).String()
			reader, err := newDiscoverySumDBReader(context.Background(), owned, proxy)
			if err != nil {
				t.Fatal(err)
			}
			transport := new(forbiddenChecksumTransport)
			reader.Client = &http.Client{Transport: transport}
			tile := tlog.Tile{H: 8, L: 0, N: 0, W: 10}
			filename := filepath.Join(reader.Cache, filepath.FromSlash(tile.Path()))
			if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, filename, string(contents))
			if _, err := reader.ReadTiles([]tlog.Tile{tile}); err == nil || transport.requests != 0 {
				t.Fatalf("bad owned cache data was hidden by a fallback: requests=%d, error=%v", transport.requests, err)
			}
		})
	}
}

func TestDiscoveryChecksumReadonlyCacheFullTilesStillSatisfyExactPrefixes(t *testing.T) {
	shared := t.TempDir()
	proxy := (&url.URL{Scheme: "file", Path: filepath.ToSlash(shared)}).String()
	reader, err := newDiscoverySumDBReader(context.Background(), t.TempDir(), proxy)
	if err != nil {
		t.Fatal(err)
	}
	transport := new(forbiddenChecksumTransport)
	reader.Client = &http.Client{Transport: transport}
	full := tlog.Tile{H: 8, L: 2, N: 3, W: 256}
	data := bytes.Repeat([]byte{0x5a}, full.W*tlog.HashSize)
	filename := filepath.Join(shared, "sumdb", "sum.golang.org", filepath.FromSlash(full.Path()))
	if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filename, string(data))
	partial := full
	partial.W = 242
	actual, err := reader.ReadTiles([]tlog.Tile{partial})
	if err != nil || len(actual) != 1 || !bytes.Equal(actual[0], data[:partial.W*tlog.HashSize]) || transport.requests != 0 {
		t.Fatalf("readonly full-tile reuse changed: requests=%d, error=%v", transport.requests, err)
	}
}

func TestDiscoveryChecksumReadonlyProxyRejectsUnboundedOrNonlocalLocations(t *testing.T) {
	for _, proxy := range []string{
		"file:relative", "file://remote.invalid/cache", "file:///cache?changed=1",
		"file:///cache#fragment", "file://user@/cache", "file://%invalid",
	} {
		if _, err := newDiscoverySumDBReader(context.Background(), t.TempDir(), proxy); err == nil {
			t.Fatalf("invalid file-proxy source accepted: %q", proxy)
		}
	}
	if _, err := newDiscoverySumDBReader(context.Background(), "relative", "off"); err == nil {
		t.Fatal("relative owned checksum cache accepted")
	}
	shared := t.TempDir()
	proxy := (&url.URL{Scheme: "file", Path: filepath.ToSlash(shared)}).String()
	reader, err := newDiscoverySumDBReader(context.Background(), t.TempDir(), proxy+"|"+proxy+",https://proxy.golang.org,direct")
	if err != nil || len(reader.ReadonlyCaches) != 1 {
		t.Fatalf("exact duplicate cache roots were not normalized: %v", err)
	}
	var proxies string
	for index := 0; index < 9; index++ {
		proxies += (&url.URL{Scheme: "file", Path: filepath.ToSlash(filepath.Join(shared, fmt.Sprint(index)))}).String() + ","
	}
	if _, err := newDiscoverySumDBReader(context.Background(), t.TempDir(), proxies); err == nil {
		t.Fatal("unbounded readonly cache roots accepted")
	}
}
