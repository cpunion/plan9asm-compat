package main

import (
	"context"
	"reflect"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

var discoveryFeatureSubtools = []string{"asm", "compile", "link", "nm", "vet"}

type discoveryFeatureToolState struct {
	directory  string
	digests    map[string]string
	origins    map[string]string
	routing    string
	dispatcher string
}

func captureDiscoveryFeatureSubtools(ctx context.Context, binary string, env []string, actual map[string]string) (*discoveryFeatureToolState, error) {
	state, err := gotoolprofile.CaptureSubtools(ctx, binary, env, actual, runDiscoveryMachineCommand)
	if err != nil {
		return nil, err
	}
	return &discoveryFeatureToolState{directory: state.Directory, digests: state.Digests, origins: state.Origins, routing: state.Routing, dispatcher: state.Dispatcher}, nil
}
func validDiscoveryFeatureToolDirectory(directory string) bool {
	return gotoolprofile.ValidToolDirectory(directory)
}
func equalDiscoveryFeatureToolStates(a, b *discoveryFeatureToolState) bool {
	return a != nil && b != nil && a.directory == b.directory && a.routing == b.routing && a.dispatcher == b.dispatcher &&
		reflect.DeepEqual(a.digests, b.digests) && reflect.DeepEqual(a.origins, b.origins)
}
