package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/build/constraint"
	"sort"
	"strings"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

// This private comparison view is never evidence and cannot pass a report or
// ledger reader: physical tool identities are deliberately absent. Call only
// after both original snapshots independently pass requireVerifiedAssemblyLedger.
// All unlisted fields stay intact, so a new proof field is compared by default.
func semanticAssemblyLedgerProgress(original discoveryProgress) (discoveryProgress, error) {
	var result discoveryProgress
	encoded, err := json.Marshal(original)
	if err != nil {
		return result, err
	}
	if err := json.Unmarshal(encoded, &result); err != nil {
		return result, err
	}
	result.Source.Revision = ""
	result.Provenance = &discoveryCorpusProvenance{
		CPPSourceProtocol:                 original.Provenance.CPPSourceProtocol,
		InstrumentationScopeProtocol:      original.Provenance.InstrumentationScopeProtocol,
		InstrumentationTypeSourceProtocol: original.Provenance.InstrumentationTypeSourceProtocol,
		DocumentationSourceProtocol:       original.Provenance.DocumentationSourceProtocol,
		SignatureSourceProtocol:           original.Provenance.SignatureSourceProtocol,
		TestDependencySourceProtocol:      original.Provenance.TestDependencySourceProtocol,
		GoVersion:                         original.Provenance.GoVersion,
		TranslatorGo:                      original.Provenance.TranslatorGo,
		// Each original already matched the anchored LLVM 22.x.y identity
		// rule. Only the cross-host contract discards patch differences.
		LLVMVersion: "22",
	}
	identities := make(map[string]string)
	inventory := newDiscoveryFeatureInventory()
	inventory.Protocol = "semantic_go_feature_comparison_v1"
	projectFeature := func(observed *discoveryTargetFeatures) {
		observed.DriverSHA256 = ""
		observed.ToolDirectory, observed.ToolRoutingSHA256 = "", ""
		observed.ToolBinarySHA256, observed.ToolBinaryOrigins = nil, nil
		observed.EnvStderrSHA256, observed.EnvRecheckStderrSHA256, observed.ListStderrSHA256 = "", "", ""
	}
	for physicalID, observed := range result.FeatureInventory.Observations {
		projectFeature(observed)
		// Target environment, version, registered sources/dispatcher, marker
		// bytes and selected builtin tags remain part of this semantic identity.
		semanticID := discoveryFeatureProfileID(observed)
		identities[physicalID] = semanticID
		if previous := inventory.Observations[semanticID]; previous != nil {
			before, err := json.Marshal(previous)
			if err != nil {
				return result, err
			}
			after, err := json.Marshal(observed)
			if err != nil || !bytes.Equal(before, after) {
				return result, fmt.Errorf("conflicting semantic profile identity")
			}
		} else {
			inventory.Observations[semanticID] = observed
		}
	}
	result.FeatureInventory = inventory
	replaceID := func(id *string) error {
		if *id == "" {
			return nil // Separately validated exception protocols have no profile.
		}
		mapped, found := identities[*id]
		if !found {
			return fmt.Errorf("profile comparison has an unbound physical identity")
		}
		*id = mapped
		return nil
	}
	projectMetadata := func(metadata *gotoolprofile.MetadataProof) error {
		if metadata == nil {
			return nil
		}
		if err := replaceID(&metadata.ProfileID); err != nil {
			return err
		}
		for index := range metadata.Packages {
			if err := replaceID(&metadata.Packages[index].Macros.FeatureID); err != nil {
				return err
			}
		}
		for index := range metadata.Headers {
			header := &metadata.Headers[index]
			if err := replaceID(&header.ProfileID); err != nil {
				return err
			}
			// Both complete originals were independently verified first.
			// Full definitions, selected sources, imports, role, language and
			// target remain exact; only physical compiler/archive bytes differ.
			header.CompileToolSHA256, header.HeaderSHA256, header.ObjectSHA256 = "", "", ""
			for index := range header.Imports {
				header.Imports[index].ExportSHA256 = ""
			}
		}
		if metadata.Dependencies != nil {
			for index := range metadata.Dependencies.ExternalPackages {
				metadata.Dependencies.ExternalPackages[index].ExportSHA256 = ""
			}
			for index := range metadata.Dependencies.SourceModules {
				if origin := metadata.Dependencies.SourceModules[index].ProxyGoMod; origin != nil {
					origin.SignedTree, origin.Inclusion = "", nil
				}
			}
		}
		return nil
	}
	projectNativeAssembly := func(cpp *gotoolprofile.CPPProof) error {
		witness := cpp.EmptyAssembly
		if cpp.DataOnlyAssembly != nil {
			witness = &cpp.DataOnlyAssembly.Native
		}
		if witness == nil {
			return nil
		}
		if err := replaceID(&witness.ProfileID); err != nil {
			return err
		}
		// Both originals passed strict validation before this private view.
		// Keep source, native listing and complete data-symbol semantics.
		witness.AsmToolSHA256, witness.ObjectSHA256 = "", ""
		return nil
	}
	projectTestDependencies := func(dependency *gotoolprofile.TestDependencyProof) error {
		if dependency == nil {
			return nil
		}
		for index := range dependency.ExternalPackages {
			// Each side already binds these physical export bytes to its actual
			// pre/post producer and consumer. Source/module/ImportMap selection
			// stays exact during the cross-host semantic comparison.
			dependency.ExternalPackages[index].ExportSHA256 = ""
		}
		for index := range dependency.SourceModules {
			if metadata := dependency.SourceModules[index].ProxyGoMod; metadata != nil {
				// Each original signature and inclusion was independently
				// verified. Preserve exact record, metadata and ZIP identities.
				metadata.SignedTree, metadata.Inclusion = "", nil
			}
		}
		selection := dependency.Query.Selection
		if err := replaceID(&selection.ProfileID); err != nil {
			return err
		}
		for index := range selection.Packages {
			if err := replaceID(&selection.Packages[index].Macros.FeatureID); err != nil {
				return err
			}
		}
		if err := projectMetadata(selection.GeneratedHeaders); err != nil {
			return err
		}
		for index := range selection.CPP {
			if err := projectNativeAssembly(&selection.CPP[index]); err != nil {
				return err
			}
		}
		return nil
	}
	for index := range result.Candidates {
		candidate := &result.Candidates[index]
		for index := range candidate.FeatureProfiles {
			if err := replaceID(&candidate.FeatureProfiles[index].ID); err != nil {
				return result, err
			}
		}
		for index := range candidate.BuildConfigurations {
			if err := replaceID(&candidate.BuildConfigurations[index].ProfileID); err != nil {
				return result, err
			}
		}
		if plan := candidate.OrdinarySelectionPlan; plan != nil {
			if modes := plan.InstrumentationPlan; modes != nil {
				requirementIDs := make(map[string]string)
				for index := range modes.Requirements {
					requirement := &modes.Requirements[index]
					physicalID := requirement.ID
					if err := replaceID(&requirement.BaselineID); err != nil {
						return result, err
					}
					requirement.ID = ""
					data, err := json.Marshal(requirement)
					if err != nil {
						return result, err
					}
					requirement.ID = discoveryFeatureBytesSHA256(data)
					requirementIDs[physicalID] = requirement.ID
				}
				for index := range modes.Outcomes {
					outcome := &modes.Outcomes[index]
					id, found := requirementIDs[outcome.RequirementID]
					if !found {
						return result, fmt.Errorf("mode comparison has an unbound source requirement")
					}
					outcome.RequirementID = id
					if excluded := outcome.TargetExclusion; excluded != nil {
						projectFeature(excluded.Early.BaselineFeatures)
						excluded.Early.ModeTools.Directory = ""
						excluded.Early.ModeTools.BinarySHA256 = nil
						excluded.Early.ModeTools.BinaryOrigins = nil
						excluded.Early.ModeTools.RoutingSHA256 = ""
						// Exact source rules, target/CGO/overrides, custom tags,
						// both command argv, Exit2/stdout/stderr and all counts stay.
					}
				}
				// Existing eligible-mode export/input/object identities remain
				// exact. This deliberately conservative comparison does not
				// grant cross-host equivalence to unprojected physical proofs.
			}
			for index := range plan.DocumentationPackages {
				proof := &plan.DocumentationPackages[index]
				if err := replaceID(&proof.ProfileID); err != nil {
					return result, err
				}
				if err := replaceID(&proof.Package.Macros.FeatureID); err != nil {
					return result, err
				}
				proof.DriverSHA256 = ""
			}
			if err := sortSemanticRows(plan.DocumentationPackages); err != nil {
				return result, err
			}
			for index := range plan.FortranRejections {
				proof := &plan.FortranRejections[index]
				if err := replaceID(&proof.ProfileID); err != nil {
					return result, err
				}
				if err := replaceID(&proof.Package.Macros.FeatureID); err != nil {
					return result, err
				}
				proof.DriverSHA256 = ""
			}
			if err := sortSemanticRows(plan.FortranRejections); err != nil {
				return result, err
			}
			for index := range plan.MixedPackageRejections {
				proof := &plan.MixedPackageRejections[index]
				if err := replaceID(&proof.ProfileID); err != nil {
					return result, err
				}
				if err := replaceID(&proof.Package.Macros.FeatureID); err != nil {
					return result, err
				}
				// Each original independently validates this physical receipt.
				// Portable names/directory, complete source rules, command,
				// source roles, exit and diagnostics remain exact.
				proof.DriverSHA256, proof.OriginalDiagnosticSHA256 = "", ""
			}
			if err := sortSemanticRows(plan.MixedPackageRejections); err != nil {
				return result, err
			}
			for index := range plan.SDKNamespaceRejections {
				proof := &plan.SDKNamespaceRejections[index]
				if err := replaceID(&proof.ProfileID); err != nil {
					return result, err
				}
				if err := replaceID(&proof.Macros.FeatureID); err != nil {
					return result, err
				}
				// Both inputs first validate their complete physical receipts.
				proof.DriverSHA256 = ""
			}
			if err := sortSemanticRows(plan.SDKNamespaceRejections); err != nil {
				return result, err
			}
			for index := range plan.PreCPPRejections {
				proof := &plan.PreCPPRejections[index]
				if err := replaceID(&proof.ProfileID); err != nil {
					return result, err
				}
				if err := replaceID(&proof.Package.Macros.FeatureID); err != nil {
					return result, err
				}
				proof.DriverSHA256, proof.AsmToolSHA256 = "", ""
			}
			if err := sortSemanticRows(plan.PreCPPRejections); err != nil {
				return result, err
			}
			for index := range plan.TestDeclarationQueries {
				query := &plan.TestDeclarationQueries[index]
				if err := replaceID(&query.ProfileID); err != nil {
					return result, err
				}
				if err := projectTestDependencies(query.Dependency); err != nil {
					return result, err
				}
			}
			if err := sortSemanticRows(plan.TestDeclarationQueries); err != nil {
				return result, err
			}
			for index := range plan.GeneratedHeaders {
				query := &plan.GeneratedHeaders[index]
				if err := replaceID(&query.ProfileID); err != nil {
					return result, err
				}
				if err := projectMetadata(query.Metadata); err != nil {
					return result, err
				}
			}
			if err := sortSemanticRows(plan.GeneratedHeaders); err != nil {
				return result, err
			}
			if role := plan.HeaderPlanning; role != nil {
				for index := range role.Queries {
					query := &role.Queries[index]
					if err := replaceID(&query.Profile.ID); err != nil {
						return result, err
					}
					if err := projectMetadata(query.Metadata); err != nil {
						return result, err
					}
				}
				if err := sortSemanticRows(role.Queries); err != nil {
					return result, err
				}
			}
			if metadata := plan.ProxyGoMod; metadata != nil {
				// Each original inclusion/signature was verified first. Tree
				// checkpoints may advance between hosts; exact authenticated
				// record, ZIP/mod sums, bytes and declared origin stay intact.
				metadata.SignedTree, metadata.Inclusion = "", nil
			}
			// This legacy host default is not used by schema10 replay. Its
			// actual target ToolTags remain in every required observation.
			plan.ToolTags = nil
			for index := range plan.ProfileDecisions {
				if err := replaceID(&plan.ProfileDecisions[index].ProfileID); err != nil {
					return result, err
				}
			}
			if err := sortSemanticRows(plan.ProfileDecisions); err != nil {
				return result, err
			}
		}
		if plan := candidate.NativeLayoutPlan; plan != nil {
			if err := keepReferencedNativeToolTags(plan); err != nil {
				return result, err
			}
			for selectionIndex := range plan.Selections {
				for decisionIndex := range plan.Selections[selectionIndex].Decisions {
					decision := &plan.Selections[selectionIndex].Decisions[decisionIndex]
					decision.Reason, err = semanticSourceReason(decision.Reason)
					if err != nil {
						return result, err
					}
				}
			}
		}
		for index := range candidate.SourceNotApplicableItems {
			item := &candidate.SourceNotApplicableItems[index]
			if err := replaceID(&item.ProfileID); err != nil {
				return result, err
			}
			if item.Diagnostic != nil {
				item.Diagnostic.SHA256 = "" // Keep protocol and all source positions.
			}
		}
		for index := range candidate.NotApplicableItems {
			if err := replaceID(&candidate.NotApplicableItems[index].ProfileID); err != nil {
				return result, err
			}
		}
		for _, proof := range candidate.FeatureConsumption {
			if err := projectTestDependencies(proof.TestDependencies); err != nil {
				return result, err
			}
			testDigests := make(map[string]string)
			for index := range proof.TestDeclarations {
				test := &proof.TestDeclarations[index]
				originalDigest := gotoolprofile.TestDeclarationSHA256(*test)
				if err := replaceID(&test.ProfileID); err != nil {
					return result, err
				}
				test.DriverSHA256, test.CompileToolSHA256, test.ExportSHA256 = "", "", ""
				for imported := range test.Imports {
					test.Imports[imported].ExportSHA256 = ""
				}
				testDigests[originalDigest] = gotoolprofile.TestDeclarationSHA256(*test)
			}
			if err := projectMetadata(proof.GeneratedHeaders); err != nil {
				return result, err
			}
			if err := replaceID(&proof.ProfileID); err != nil {
				return result, err
			}
			for index := range proof.Packages {
				if err := replaceID(&proof.Packages[index].Macros.FeatureID); err != nil {
					return result, err
				}
			}
			for index := range proof.Outputs {
				proof.Outputs[index].IR, proof.Outputs[index].Object = "", ""
			}
			for index := range proof.CPP {
				for signature := range proof.CPP[index].Signatures {
					source := &proof.CPP[index].Signatures[signature]
					if source.TestProofSHA256 != "" {
						projected, found := testDigests[source.TestProofSHA256]
						if !found {
							return result, fmt.Errorf("semantic test declaration has an unbound physical witness")
						}
						source.TestProofSHA256 = projected
					}
				}
				if err := projectNativeAssembly(&proof.CPP[index]); err != nil {
					return result, err
				}
			}
			if err := sortSemanticRows(proof.Packages); err != nil {
				return result, err
			}
			if err := sortSemanticRows(proof.CPP); err != nil {
				return result, err
			}
			if err := sortSemanticRows(proof.Outputs); err != nil {
				return result, err
			}
		}
		for _, err := range []error{
			sortSemanticRows(candidate.FeatureProfiles), sortSemanticRows(candidate.BuildConfigurations),
			sortSemanticRows(candidate.SourceNotApplicableItems), sortSemanticRows(candidate.NotApplicableItems),
			sortSemanticRows(candidate.FeatureConsumption),
		} {
			if err != nil {
				return result, err
			}
		}
	}
	return result, nil
}

// Retain every true feature referenced by any saved native constraint, even
// when an OR expression leaves selection unchanged. An absent referenced tag
// remains false. Only demonstrably unused host tags may disappear.
func keepReferencedNativeToolTags(plan *discoveryNativeLayoutPlan) error {
	referenced := make(map[string]bool)
	for _, source := range plan.SourceInventory {
		for _, line := range strings.Split(source.Header, "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "//go:build ") && !strings.HasPrefix(line, "// +build ") {
				continue
			}
			expression, err := constraint.Parse(line)
			if err != nil {
				return fmt.Errorf("native comparison cannot parse original constraint: %w", err)
			}
			collectDiscoveryConstraintTags(expression, referenced)
		}
	}
	var retained []string
	for _, tag := range plan.ToolTags {
		if referenced[tag] {
			retained = append(retained, tag)
		}
	}
	plan.ToolTags = uniqueSortedDiscoveryStrings(retained)
	return nil
}

func semanticSourceReason(reason string) (string, error) {
	witness := captureDiscoverySourceDiagnostic(reason)
	if witness == nil {
		return reason, nil // Never erase unclassified/selection diagnostics.
	}
	witness.SHA256 = ""
	data, err := json.Marshal(witness)
	return string(data), err
}

func sortSemanticRows[T any](rows []T) error {
	keys := make([][]byte, len(rows))
	indices := make([]int, len(rows))
	for index := range rows {
		encoded, err := json.Marshal(rows[index])
		if err != nil {
			return err
		}
		keys[index], indices[index] = encoded, index
	}
	sort.Slice(indices, func(i, j int) bool { return bytes.Compare(keys[indices[i]], keys[indices[j]]) < 0 })
	ordered := make([]T, len(rows))
	for index, original := range indices {
		ordered[index] = rows[original]
	}
	copy(rows, ordered)
	return nil
}
