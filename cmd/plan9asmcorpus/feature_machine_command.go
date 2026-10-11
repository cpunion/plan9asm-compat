package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func runDiscoveryMachineCommand(ctx context.Context, dir string, env []string, name string, args ...string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir, cmd.Env, cmd.WaitDelay = dir, env, 2*time.Second
	var stdout, stderr boundedDiscoveryCommandOutput
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := runDiscoveryCommand(cmd)
	if ctx.Err() != nil {
		return nil, nil, fmt.Errorf("%s: %w", name, ctx.Err())
	}
	if stdout.truncated || stderr.truncated {
		return nil, nil, fmt.Errorf("%s: %w", name, errDiscoveryCommandOutputExceeded)
	}
	if err != nil {
		output := "stdout:\n" + stdout.String() + "\nstderr:\n" + stderr.String()
		display := output
		if len(display) > 64<<10 {
			display = "... output truncated ...\n" + display[len(display)-(64<<10):]
		}
		return stdout.Bytes(), stderr.Bytes(), &discoveryCapturedCommandError{
			command: strings.Join(append([]string{name}, args...), " "), cause: err, output: output, display: display,
		}
	}
	return stdout.Bytes(), stderr.Bytes(), nil
}

func discoveryFeatureBytesSHA256(data []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

func discoveryFeatureProfileID(observed *discoveryTargetFeatures) string {
	return gotoolprofile.ProfileID(observed)
}

func containsTargetFeature(tags []string, wanted string) bool {
	for _, tag := range tags {
		if tag == wanted {
			return true
		}
	}
	return false
}
