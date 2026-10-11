package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoveryProgressPreparationGuards(t *testing.T) {
	for _, kind := range []string{"complete", "changed bytes", "replacement", "symlink", "parent replacement", "late destination"} {
		t.Run(kind, func(t *testing.T) {
			container := t.TempDir()
			parent := filepath.Join(container, "output")
			if err := os.Mkdir(parent, 0700); err != nil {
				t.Fatal(err)
			}
			filename := filepath.Join(parent, "assembly-progress.json")
			prepared, err := prepareDiscoveryProgressOutput(filename, discoveryProgress{})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(filename); !os.IsNotExist(err) {
				t.Fatal("preparation published before frozen-input checks")
			}
			var foreign string
			switch kind {
			case "changed bytes":
				writeTestFile(t, prepared.temporary, "foreign bytes in the original inode\n")
			case "replacement", "symlink":
				if err := os.Rename(prepared.temporary, filepath.Join(container, "original-temporary")); err != nil {
					t.Fatal(err)
				}
				foreign = prepared.temporary
				if kind == "symlink" {
					foreign = filepath.Join(container, "foreign.json")
					writeTestFile(t, foreign, "foreign evidence\n")
					if err := os.Symlink(foreign, prepared.temporary); err != nil {
						t.Fatal(err)
					}
				} else {
					writeTestFile(t, foreign, "foreign evidence\n")
				}
			case "parent replacement":
				if err := os.Rename(parent, filepath.Join(container, "original-parent")); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(parent, 0700); err != nil {
					t.Fatal(err)
				}
				foreign = prepared.temporary
				writeTestFile(t, foreign, "foreign evidence\n")
			case "late destination":
				foreign = filename
				writeTestFile(t, foreign, "foreign evidence\n")
			}
			err = prepared.publish()
			cleanupErr := prepared.discard()
			if kind == "complete" {
				if err != nil || cleanupErr != nil {
					t.Fatalf("complete publication: %v %v", err, cleanupErr)
				}
			} else if err == nil {
				t.Fatal("changed or occupied preparation was published")
			}
			if kind == "replacement" || kind == "symlink" || kind == "parent replacement" {
				if cleanupErr == nil || !strings.Contains(cleanupErr.Error(), "changed") {
					t.Fatalf("foreign temporary cleanup was not rejected: %v", cleanupErr)
				}
			} else if cleanupErr != nil {
				t.Fatalf("owned temporary cleanup: %v", cleanupErr)
			}
			if foreign != "" {
				data, err := os.ReadFile(foreign)
				if err != nil || string(data) != "foreign evidence\n" {
					t.Fatalf("foreign replacement changed: %q %v", data, err)
				}
			}
			if kind != "complete" && kind != "late destination" {
				if _, err := os.Lstat(filename); !os.IsNotExist(err) {
					t.Fatalf("invalid preparation emitted progress: %v", err)
				}
			}
		})
	}
}
