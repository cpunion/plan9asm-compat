//go:build go1.27

package main

import "testing"

// Complete first-party source, compiler/header, CPP and LLVM consumers must
// still agree after omitting uninstantiated types from the property roots.
// The shared driver checks all eleven target scopes and portable mutations;
// the imported dependency is independently compiled from these original bytes.
func TestCPPUninstantiatedGenericImportedHeaderFullDefaultOriginalObjects(t *testing.T) {
	testCPPActiveGeneratedHeaderFullDefaultOriginalObjects(t, `package header
import dep "example.invalid/active-header/dependency"
type Record struct { Value uint64 }
const Value = 7
type Frame[R, S any] struct { state *State[R, S] }
type State[R, S any] struct { recv R; send S; inner[R] }
type inner[R any] struct { next chan R }
var UnusedByHeader = dep.New("initializer")
//go:nosplit
//go:noinline
func Holder() { _ = dep.New("function body") }
func Probe()
`, map[string]string{
		"dependency/value.go": "package dependency\nfunc New(value string) string { return value }\n",
	})
}
