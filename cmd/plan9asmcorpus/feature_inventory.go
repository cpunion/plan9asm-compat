package main

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Observations are shared across candidates. Source-dependent requests remain
// in each candidate's plan: the same actual environment can satisfy different
// source constraints without duplicating the complete builtin namespace.
type discoveryFeatureInventory struct {
	Protocol     string                              `json:"protocol"`
	Observations map[string]*discoveryTargetFeatures `json:"observations"`
}

type discoveryFeatureProfileReference struct {
	ID      string                         `json:"id"`
	Request discoveryFeatureProfileRequest `json:"request"`
}

const discoveryFeatureInventoryProtocol = "go_driver_feature_inventory_v1"

func newDiscoveryFeatureInventory() *discoveryFeatureInventory {
	return &discoveryFeatureInventory{
		Protocol:     discoveryFeatureInventoryProtocol,
		Observations: make(map[string]*discoveryTargetFeatures),
	}
}

func mergeDiscoveryFeatureInventory(destination, source *discoveryFeatureInventory) error {
	if err := validateDiscoveryFeatureInventory(source); err != nil {
		return err
	}
	if err := validateDiscoveryFeatureInventory(destination); err != nil {
		return err
	}
	for _, id := range sortedDiscoveryFeatureInventoryIDs(source) {
		_, err := registerDiscoveryFeatureProfiles(destination, []discoveryFeatureProfile{{ID: id, Observed: source.Observations[id]}})
		if err != nil {
			return err
		}
	}
	return nil
}

func sortedDiscoveryFeatureInventoryIDs(inventory *discoveryFeatureInventory) []string {
	set := make(map[string]bool)
	for id := range inventory.Observations {
		set[id] = true
	}
	return sortedDiscoverySet(set)
}

func registerDiscoveryFeatureProfiles(inventory *discoveryFeatureInventory, profiles []discoveryFeatureProfile) ([]discoveryFeatureProfileReference, error) {
	if inventory == nil || len(profiles) == 0 {
		return nil, fmt.Errorf("missing actual feature inventory or observations")
	}
	if inventory.Protocol == "" && len(inventory.Observations) == 0 {
		inventory.Protocol = discoveryFeatureInventoryProtocol
		inventory.Observations = make(map[string]*discoveryTargetFeatures)
	}
	if err := validateDiscoveryFeatureInventory(inventory); err != nil {
		return nil, err
	}
	var references []discoveryFeatureProfileReference
	seen := make(map[string]bool)
	for _, profile := range profiles {
		if err := validateDiscoveryTargetFeatures(profile.Observed); err != nil {
			return nil, err
		}
		if profile.ID != discoveryFeatureProfileID(profile.Observed) || seen[profile.ID] {
			return nil, fmt.Errorf("invalid or duplicate actual feature identity")
		}
		seen[profile.ID] = true
		canonical, err := json.Marshal(profile.Observed)
		if err != nil {
			return nil, err
		}
		if old, present := inventory.Observations[profile.ID]; present {
			previous, err := json.Marshal(old)
			if err != nil || !bytes.Equal(previous, canonical) {
				return nil, fmt.Errorf("conflicting canonical feature observations for %s", profile.ID)
			}
		} else {
			// Own the canonical bytes, not a mutable producer pointer. Later
			// source planning cannot rewrite a shared observation in place.
			var owned discoveryTargetFeatures
			if err := json.Unmarshal(canonical, &owned); err != nil {
				return nil, err
			}
			inventory.Observations[profile.ID] = &owned
		}
		requestData, err := json.Marshal(profile.Request)
		if err != nil {
			return nil, err
		}
		var request discoveryFeatureProfileRequest
		if err := json.Unmarshal(requestData, &request); err != nil {
			return nil, err
		}
		references = append(references, discoveryFeatureProfileReference{ID: profile.ID, Request: request})
	}
	return references, nil
}

func validateDiscoveryFeatureInventory(inventory *discoveryFeatureInventory) error {
	if inventory == nil || inventory.Protocol != discoveryFeatureInventoryProtocol || inventory.Observations == nil {
		return fmt.Errorf("missing or invalid actual feature inventory protocol")
	}
	for id, observed := range inventory.Observations {
		if err := validateDiscoveryTargetFeatures(observed); err != nil {
			return err
		}
		if id != discoveryFeatureProfileID(observed) {
			return fmt.Errorf("feature inventory ID does not match canonical observation bytes")
		}
	}
	return nil
}

func resolveDiscoveryFeatureProfiles(inventory *discoveryFeatureInventory, references []discoveryFeatureProfileReference) ([]discoveryFeatureProfile, error) {
	if err := validateDiscoveryFeatureInventory(inventory); err != nil {
		return nil, err
	}
	if len(references) == 0 {
		return nil, fmt.Errorf("missing source-required feature profile references")
	}
	var profiles []discoveryFeatureProfile
	seen := make(map[string]bool)
	for _, reference := range references {
		observed, present := inventory.Observations[reference.ID]
		if !present || seen[reference.ID] {
			return nil, fmt.Errorf("unresolved or duplicate source-required feature reference %s", reference.ID)
		}
		seen[reference.ID] = true
		profiles = append(profiles, discoveryFeatureProfile{ID: reference.ID, Request: reference.Request, Observed: observed})
	}
	return profiles, nil
}
