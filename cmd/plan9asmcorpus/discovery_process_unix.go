//go:build unix

package main

import (
	"errors"
	"os/exec"

	"github.com/llgo-compat/plan9asm/internal/ownedprocess"
)

func runDiscoveryCommand(cmd *exec.Cmd) error {
	err := ownedprocess.Run(cmd)
	if errors.Is(err, ownedprocess.ErrCleanup) {
		return errors.Join(err, errDiscoveryCommandCleanup)
	}
	return err
}
