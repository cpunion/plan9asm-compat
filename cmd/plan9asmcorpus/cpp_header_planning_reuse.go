package main

import "encoding/json"

// This operation-owned collection remembers only observations whose full
// source preflight rejected the closed generated-header model. It is not part
// of any report or feature inventory. Every hit reruns the original source
// checks; final compiler profiles always use the actual observation producer.
// Like its enclosing plan's query slice, this state has one owner: synchronous
// profile planning and replay invoke the callback until the producer clears it
// before returning. Concurrent candidates own separate plans and collections.
type discoveryHeaderPreflightReuse struct {
	profiles map[string][]byte
	bytes    int
}

const (
	discoveryHeaderPreflightEntryLimit = 4096
	discoveryHeaderPreflightByteLimit  = 16 << 20
)

func (reuse *discoveryHeaderPreflightReuse) lookup(key string) (*discoveryTargetFeatures, error) {
	data, found := reuse.profiles[key]
	if !found {
		return nil, nil
	}
	var observed discoveryTargetFeatures
	if err := json.Unmarshal(data, &observed); err != nil {
		return nil, err
	}
	return &observed, nil
}

func (reuse *discoveryHeaderPreflightReuse) remember(key string, observed *discoveryTargetFeatures) error {
	if _, found := reuse.profiles[key]; found || len(reuse.profiles) >= discoveryHeaderPreflightEntryLimit ||
		len(key) > discoveryHeaderPreflightByteLimit-reuse.bytes {
		return nil
	}
	data, err := json.Marshal(observed)
	if err != nil {
		return err
	}
	if len(data) > discoveryHeaderPreflightByteLimit-reuse.bytes-len(key) {
		return nil // Reuse is an optimization, not another acceptance limit.
	}
	if reuse.profiles == nil {
		reuse.profiles = make(map[string][]byte)
	}
	reuse.profiles[key] = data
	reuse.bytes += len(key) + len(data)
	return nil
}

func (reuse *discoveryHeaderPreflightReuse) remove(key string) {
	if data, found := reuse.profiles[key]; found {
		reuse.bytes -= len(key) + len(data)
		delete(reuse.profiles, key)
	}
}
