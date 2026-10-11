package main

import "fmt"

// One planning invocation owns this pure parser/lexical index. It contains no plan,
// validation receipt, source grant or caller-supplied projection. Parsing has
// one fixed full-original mode; its complete key is the filename and text.
// All public fields and graph relationships are still checked on every use.
type discoveryCPPPlanningSourceIndex struct {
	sources map[discoveryCPPPlanningSourceKey]discoveryCPPSource
	bytes   int

	lexical      map[discoveryCPPPlanningSourceKey]bool
	lexicalBytes int
}

type discoveryCPPPlanningSourceKey struct{ file, text string }

// Only the pure lexical answer is reusable, keyed by the complete original
// text and filename. Callers still validate source projections, graph edges,
// generated-header roles and cancellation on every query. Like parsed sources,
// this private map has an independent finite file/byte bound and is never
// serialized or shared between planning invocations.
func (index *discoveryCPPPlanningSourceIndex) conditionFreeText(text, file string) bool {
	if index == nil || len(text) > discoveryReplayCPPGraphBytes {
		return discoveryCPPConditionFreeText(text, file)
	}
	key := discoveryCPPPlanningSourceKey{file: file, text: text}
	if result, found := index.lexical[key]; found {
		return result
	}
	result := discoveryCPPConditionFreeText(text, file)
	if len(index.lexical) >= 512 || len(text) > discoveryReplayCPPGraphBytes-index.lexicalBytes {
		index.lexical, index.lexicalBytes = nil, 0
	}
	if index.lexical == nil {
		index.lexical = make(map[discoveryCPPPlanningSourceKey]bool)
	}
	index.lexical[key] = result
	index.lexicalBytes += len(text)
	return result
}

func (index *discoveryCPPPlanningSourceIndex) validate(file string, source discoveryCPPSource) (*discoveryCPPSourceResourceIndex, error) {
	if source.Original == nil {
		return nil, fmt.Errorf("CPP source index requires complete original bytes")
	}
	key := discoveryCPPPlanningSourceKey{file: file, text: *source.Original}
	var actual discoveryCPPSource
	var found bool
	if index != nil {
		actual, found = index.sources[key]
	}
	if !found {
		var err error
		actual, err = discoveryReplayCPPSourceText(file, key.text)
		if err != nil {
			return nil, err
		}
	}
	if !equalDiscoveryCPPSource(source, actual) {
		return nil, fmt.Errorf("CPP public source projection differs from complete original parse")
	}
	if index != nil && !found {
		// Keep the original graph's file/byte budget even if a callback
		// changes complete inputs. Eviction affects cost, never admission.
		if len(index.sources) >= 512 || len(key.text) > discoveryReplayCPPGraphBytes-index.bytes {
			index.sources, index.bytes = nil, 0
		}
		if index.sources == nil {
			index.sources = make(map[discoveryCPPPlanningSourceKey]discoveryCPPSource)
		}
		index.sources[key] = actual
		index.bytes += len(key.text)
	}
	// Only the parser's immutable resource index leaves this method. In
	// particular, public Original pointers and Directives slices never alias
	// the cached parse, including when a caller mutates its own projection.
	return actual.resourceIndex, nil
}
