//go:build unix

package ownedprocess

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// ErrCleanup distinguishes descendant cleanup failures from the command exit.
var ErrCleanup = errors.New("owned command descendants")

type groupMember struct {
	PID   int
	PGID  int
	State string
}

type groupObserver func(int) ([]groupMember, error)

// Run owns only this command's newly created process group. Both cancellation
// and ordinary parent exit stop descendants before the caller removes files.
func Run(command *exec.Cmd) error {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		return stopGroup(command.Process.Pid, false, syscall.Kill, observeProcessGroup)
	}
	err := command.Run()
	if command.Process != nil {
		cleanup := stopGroup(command.Process.Pid, command.ProcessState != nil, syscall.Kill, observeProcessGroup)
		if cleanup != nil && !errors.Is(cleanup, os.ErrProcessDone) {
			err = errors.Join(err, fmt.Errorf("%w: %w", ErrCleanup, cleanup))
		}
	}
	return err
}

func stopGroup(pgid int, parentReaped bool, kill func(int, syscall.Signal) error, observe groupObserver) error {
	if pgid <= 1 {
		return fmt.Errorf("refuse an unowned process group: %d", pgid)
	}
	err := kill(-pgid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	if !errors.Is(err, syscall.EPERM) || !parentReaped || observe == nil {
		return err
	}
	members, snapshotErr := observe(pgid)
	if snapshotErr != nil {
		return errors.Join(err, fmt.Errorf("inspect exited owned group: %w", snapshotErr))
	}
	seen := make(map[int]bool, len(members))
	for _, member := range members {
		if member.PID <= 1 || member.PGID != pgid || seen[member.PID] || !validDarwinState(member.State) {
			return errors.Join(err, fmt.Errorf("owned group membership is unknown"))
		}
		seen[member.PID] = true
		if member.State[0] != 'Z' {
			return errors.Join(err, fmt.Errorf("owned group still has a live member"))
		}
	}
	// Darwin filters SZOMB from killpg1 and can report EPERM for a group
	// containing only zombies. Its waited leader and a complete independent
	// kernel snapshot establish that no member can fork or write more files.
	return os.ErrProcessDone
}

func validDarwinState(state string) bool {
	if len(state) == 0 || !strings.ContainsRune("IRSTUZ", rune(state[0])) {
		return false
	}
	for _, modifier := range state[1:] {
		if !strings.ContainsRune("+<>AELNSsVWX", modifier) {
			return false
		}
	}
	return true
}
