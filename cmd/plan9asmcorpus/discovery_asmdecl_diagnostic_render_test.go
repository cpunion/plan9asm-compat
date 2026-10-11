package main

import (
	"errors"
	"strings"
	"testing"
)

// These are deliberately synthetic display tripwires. Only the underlying
// ExitError is obtained from stock Go; the output mutations are not a native
// diagnostic receipt and must never confer source-rejection permission.
func TestDiscoveryAsmDeclDiagnosticOpaqueWrapperKeepsCompleteChild(t *testing.T) {
	failure := &discoveryCapturedCommandError{
		command: "go tool vet -asmdecl first.cfg",
		cause:   discoveryAsmDeclObservedExitOne(t),
		output:  "first-complete-start\nunknown first analysis diagnostic\nfirst-complete-end\n",
		display: "first compact display",
	}
	wrapper := discoveryAsmDeclDiagnosticOpaqueWrapper{
		context: "unknown outer analysis failure",
		cause:   failure,
	}
	diagnostic := discoveryCommandDiagnostic(wrapper)
	for _, required := range []string{wrapper.context, failure.output} {
		if !strings.Contains(diagnostic, required) {
			t.Errorf("generic display lost complete wrapper/child context %q: %q", required, diagnostic)
		}
	}
	discoveryAsmDeclDiagnosticRequireNoRejectionPermission(t, wrapper)
}

func TestDiscoveryAsmDeclDiagnosticJoinedCompactCollisionKeepsBothOutputs(t *testing.T) {
	exitOne := discoveryAsmDeclObservedExitOne(t)
	second := &discoveryCapturedCommandError{
		command: "go tool vet -asmdecl second.cfg",
		cause:   exitOne,
		output:  "second-complete-start\nunknown second analysis diagnostic\nsecond-complete-end\n",
		display: "second compact display",
	}
	first := &discoveryCapturedCommandError{
		command: "go tool vet -asmdecl first.cfg",
		cause:   exitOne,
		// A complete output may contain text resembling another command's
		// compact display. Expanding that child must not rewrite these bytes.
		output:  "first-complete-start\n" + second.Error() + "\nunknown first analysis diagnostic\nfirst-complete-end\n",
		display: "first compact display",
	}
	joined := errors.Join(first, second, errors.New("unknown joined analysis failure"))
	diagnostic := discoveryCommandDiagnostic(joined)
	for _, required := range []string{first.output, second.output, "unknown joined analysis failure"} {
		if !strings.Contains(diagnostic, required) {
			t.Errorf("generic display lost or rewrote complete joined context %q: %q", required, diagnostic)
		}
	}
	discoveryAsmDeclDiagnosticRequireNoRejectionPermission(t, joined)
}

type discoveryAsmDeclDiagnosticOpaqueWrapper struct {
	context string
	cause   error
}

func (wrapper discoveryAsmDeclDiagnosticOpaqueWrapper) Error() string { return wrapper.context }
func (wrapper discoveryAsmDeclDiagnosticOpaqueWrapper) Unwrap() error { return wrapper.cause }

func discoveryAsmDeclDiagnosticRequireNoRejectionPermission(t *testing.T, err error) {
	t.Helper()
	if _, observed := discoveryAsmDeclObservedFailures(err); observed {
		t.Error("arbitrary wrapper/join acquired completed-analysis permission")
	}
	if discoveryAsmDeclOnlyKnownNonABIWarnings(err) {
		t.Error("unknown wrapped/joined diagnostics acquired non-ABI dismissal permission")
	}
	if _, complete := discoveryAsmDeclCompleteABIDiagnostics([]string{"decl_amd64.s"}, err); complete {
		t.Error("unknown wrapped/joined diagnostics acquired source-rejection permission")
	}
}
