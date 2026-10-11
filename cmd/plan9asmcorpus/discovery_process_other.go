//go:build !unix

package main

import "os/exec"

func runDiscoveryCommand(cmd *exec.Cmd) error {
	// Unix process groups are unavailable here. Foreground Git maintenance
	// and the shared WaitDelay still bound subprocess output-pipe waits.
	return cmd.Run()
}
