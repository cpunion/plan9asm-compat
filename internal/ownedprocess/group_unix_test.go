//go:build unix

package ownedprocess

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

func TestOwnedGroupPermissionRequiresExitedMembership(t *testing.T) {
	const pgid = 4123
	for _, test := range []struct {
		name         string
		parentReaped bool
		members      []groupMember
		observeErr   error
		wantDone     bool
	}{
		{name: "reaped absent", parentReaped: true, wantDone: true},
		{name: "reaped zombie descendants", parentReaped: true, members: []groupMember{{PID: 4124, PGID: pgid, State: "Z"}}, wantDone: true},
		{name: "zombie leader before wait", members: []groupMember{{PID: pgid, PGID: pgid, State: "Z"}, {PID: 4124, PGID: pgid, State: "Z+"}}},
		{name: "leader termination unknown"},
		{name: "leader missing with zombie descendant", members: []groupMember{{PID: 4124, PGID: pgid, State: "Z"}}},
		{name: "live leader", members: []groupMember{{PID: pgid, PGID: pgid, State: "S"}}},
		{name: "live descendant", parentReaped: true, members: []groupMember{{PID: 4124, PGID: pgid, State: "R"}}},
		{name: "stopped descendant", parentReaped: true, members: []groupMember{{PID: 4124, PGID: pgid, State: "T"}}},
		{name: "unknown state", parentReaped: true, members: []groupMember{{PID: 4124, PGID: pgid, State: "?"}}},
		{name: "wrong group", parentReaped: true, members: []groupMember{{PID: 4124, PGID: pgid + 1, State: "Z"}}},
		{name: "unknown pid", parentReaped: true, members: []groupMember{{PGID: pgid, State: "Z"}}},
		{name: "duplicate member", parentReaped: true, members: []groupMember{{PID: 4124, PGID: pgid, State: "Z"}, {PID: 4124, PGID: pgid, State: "Z"}}},
		{name: "inaccessible membership", parentReaped: true, observeErr: syscall.EPERM},
		{name: "snapshot unavailable", parentReaped: true, observeErr: syscall.EIO},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			err := stopGroup(pgid, test.parentReaped, func(pid int, signal syscall.Signal) error {
				if pid != -pgid || signal != syscall.SIGKILL {
					t.Fatalf("unowned signal: %d %v", pid, signal)
				}
				return syscall.EPERM
			}, func(observed int) ([]groupMember, error) {
				calls++
				if observed != pgid {
					t.Fatalf("unowned observation: %d", observed)
				}
				return test.members, test.observeErr
			})
			wantCalls := 0
			if test.parentReaped {
				wantCalls = 1
			}
			if calls != wantCalls {
				t.Fatalf("permission result lacks a post-Wait membership check: got %d want %d", calls, wantCalls)
			}
			if test.wantDone {
				if !errors.Is(err, os.ErrProcessDone) {
					t.Fatalf("independently exited group rejected: %v", err)
				}
			} else if !errors.Is(err, syscall.EPERM) || errors.Is(err, os.ErrProcessDone) {
				t.Fatalf("live/unknown/inaccessible group accepted: %v", err)
			}
		})
	}
}

func TestOwnedGroupRejectsBroadSignalTargets(t *testing.T) {
	for _, pgid := range []int{-1, 0, 1} {
		called := false
		err := stopGroup(pgid, true, func(int, syscall.Signal) error {
			called = true
			return nil
		}, nil)
		if err == nil || called {
			t.Fatalf("unowned broad target was signalled: %d %v", pgid, err)
		}
	}
}

func TestOwnedGroupOtherSignalOutcomesRemainExact(t *testing.T) {
	for _, signalErr := range []error{nil, syscall.ESRCH, syscall.EIO, syscall.EINVAL, syscall.EPERM} {
		err := stopGroup(4123, true, func(int, syscall.Signal) error { return signalErr }, nil)
		if signalErr == syscall.ESRCH {
			if !errors.Is(err, os.ErrProcessDone) {
				t.Fatalf("absent group: %v", err)
			}
		} else if err != signalErr {
			t.Fatalf("signal error changed: got %v want %v", err, signalErr)
		}
	}
}
