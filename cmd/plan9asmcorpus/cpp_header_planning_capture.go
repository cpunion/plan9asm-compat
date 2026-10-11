package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"
)

func installDiscoveryHeaderPlanning(ctx context.Context, plan *discoveryOrdinarySelectionPlan, candidate discoveryCandidate, download moduleDownloadInfo, dir, goRoot, goBinary, markers, translator string, env []string, cache *discoveryFeatureObservationCache, events ...*discoveryPhaseJournal) error {
	if len(events) > 1 {
		return fmt.Errorf("native header planning accepts one optional timing journal")
	}
	var journal *discoveryPhaseJournal
	if len(events) == 1 {
		journal = events[0]
	}
	if translator == "" {
		return nil // Historical callers retain the conservative all-CPU plan.
	}
	if !filepath.IsAbs(translator) || ctx == nil || cache == nil {
		return fmt.Errorf("native header planning requires the actual bounded query producer")
	}
	if _, bounded := ctx.Deadline(); !bounded || ctx.Err() != nil {
		return fmt.Errorf("native header planning lacks its live bounded context")
	}
	if plan.headerPlanningCapture != nil {
		return nil
	}
	var rules *gotoolprofile.NativeHeaderSourceRules
	module, err := ordinaryProfileDeclaredModule(plan)
	if err != nil {
		return err
	}
	execution, err := makeDiscoveryExecutionPlan(candidate, module)
	if err != nil {
		return err
	}
	queryModule, err := discoveryHeaderQueryGoMod(execution.GoMod, plan.GoVersion)
	if err != nil {
		return err
	}
	queryDir, err := os.MkdirTemp(dir, "native-header-planning-")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(queryDir, "go.mod"), []byte(queryModule), 0600); err != nil {
		return err
	}
	guard, err := captureDiscoveryHeaderQueryWorkspace(queryDir, queryModule)
	if err != nil {
		return err
	}
	check := func() error {
		if err := guard.verify(); err != nil {
			return err
		}
		if rules != nil {
			if err := gotoolprofile.RecheckNativeHeaderSourceRules(goRoot, rules); err != nil {
				return err
			}
		}
		if err := verifyDiscoveryOrdinaryDependencySnapshots(plan); err != nil {
			return err
		}
		if role := plan.HeaderPlanning; role != nil && len(role.ImportedSources) != 0 {
			hashes := make(map[string]string, len(role.ImportedSources))
			for file, text := range role.ImportedSources {
				hashes[file] = discoveryFeatureBytesSHA256([]byte(text))
			}
			return verifyDiscoveryOriginalSourceMap(plan, download.Dir, download.Zip, hashes)
		}
		return nil
	}
	plan.headerPlanningInventory = newDiscoveryFeatureInventory()
	plan.headerPlanningRecheck = check
	var unsupported discoveryHeaderPreflightReuse
	var viability discoveryHeaderViabilityCache
	plan.headerPlanningCapture = func(request discoveryFeatureProfileRequest, assembly string, tags []string) (header *gotoolprofile.GeneratedHeaderProof, result error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := check(); err != nil {
			return nil, err
		}
		key := discoveryHeaderPlanningKey(request, assembly, tags)
		defer func() {
			guardErr := check()
			if err := errors.Join(guardErr, ctx.Err()); err != nil {
				// A caller catches Unsupported to retain all CPU proposals. Do
				// not leave that classification reachable through a joined
				// cancellation or changed-input error.
				var unsupported *discoveryHeaderPlanningUnsupported
				if errors.As(result, &unsupported) {
					result = fmt.Errorf("native header source preflight: %s", result)
				}
				header, result = nil, errors.Join(result, err)
			}
			var sourceUnsupported *discoveryHeaderPlanningUnsupported
			if result != nil && !errors.As(result, &sourceUnsupported) {
				unsupported.remove(key)
			}
		}()
		if rules == nil {
			var err error
			rules, err = gotoolprofile.CaptureNativeHeaderSourceRules(goRoot, plan.GoVersion)
			if err != nil {
				if gotoolprofile.NativeHeaderSourceDomainUnsupported(err) {
					return nil, &discoveryHeaderPlanningUnsupported{err.Error()}
				}
				return nil, err
			}
		}
		if plan.HeaderPlanning != nil {
			if len(plan.HeaderPlanning.Queries) >= 4096 {
				return nil, fmt.Errorf("native header planning exceeds its explicit query bound")
			}
			for _, query := range plan.HeaderPlanning.Queries {
				if discoveryHeaderPlanningKey(query.Profile.Request, query.Assembly, query.BuildTags) == key {
					return replayDiscoveryPlanningHeader(plan, request, assembly, tags)
				}
			}
		}
		if observed, err := unsupported.lookup(key); err != nil {
			return nil, err
		} else if observed != nil {
			// A retained observation is only a source-predicate input. Recheck
			// complete original source/ZIP bytes on every negative reuse; it
			// cannot authorize a query or register an executed profile.
			profile := discoveryFeatureProfile{ID: discoveryFeatureProfileID(observed), Request: request, Observed: observed}
			queryPlan, err := discoveryHeaderQuerySourcePlan(plan, profile, assembly, tags)
			if err != nil {
				return nil, err
			}
			if err := preflightDiscoveryHeaderQuery(queryPlan, profile, download, assembly, tags); err != nil {
				if gotoolprofile.NativeHeaderSourceDomainUnsupported(err) {
					return nil, &discoveryHeaderPlanningUnsupported{err.Error()}
				}
				return nil, err
			}
			// A now-closed domain must obtain fresh actual tool observations
			// before generating any header or other successful proof.
			unsupported.remove(key)
		}
		observed, err := cache.observe(ctx, goBinary, markers, env, request.Target, request.Overrides)
		if err != nil {
			return nil, err
		}
		profile := discoveryFeatureProfile{ID: discoveryFeatureProfileID(observed), Request: request, Observed: observed}
		queryPlan, err := discoveryHeaderQuerySourcePlan(plan, profile, assembly, tags)
		if err != nil {
			return nil, err
		}
		if err := preflightDiscoveryHeaderQuery(queryPlan, profile, download, assembly, tags); err != nil {
			if gotoolprofile.NativeHeaderSourceDomainUnsupported(err) {
				if err := unsupported.remember(key, observed); err != nil {
					return nil, err
				}
				return nil, &discoveryHeaderPlanningUnsupported{err.Error()}
			}
			return nil, err
		}
		queryPlan.GeneratedHeaders = nil
		queryPlan.GeneratedGoSources = nil
		pattern := module
		if directory := path.Dir(assembly); directory != "." {
			pattern += "/" + directory
		}
		group := discoveryPackageGroup{Pattern: pattern, AsmFiles: []string{assembly}}
		queryEnv := ordinaryProfileEnvironment(env, observed)
		viabilityKey := discoveryHeaderViabilityKey(profile.ID, pattern, tags)
		err = viability.check(viabilityKey, func() error {
			if err := check(); err != nil {
				return err
			}
			return verifyDiscoveryOrdinaryCPP(plan, download.Dir, goRoot, candidate)
		}, func() error {
			args := []string{"list", "-export", "-mod=mod"}
			if len(tags) != 0 {
				args = append(args, "-tags="+strings.Join(tags, ","))
			}
			args = append(args, pattern)
			return journal.run(candidate.exactKey(), "ordinary_header_viability", profile.ID+"/"+pattern+"/"+strings.Join(tags, ","), func() error {
				_, _, err := runDiscoveryMachineCommand(ctx, queryDir, queryEnv, goBinary, args...)
				return err
			})
		}, func() error {
			after, err := cache.observe(ctx, goBinary, markers, env, request.Target, request.Overrides)
			if err != nil {
				return err
			}
			if discoveryFeatureProfileID(after) != profile.ID {
				return fmt.Errorf("actual package viability tool/profile changed during original Go compilation")
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		ordinal := 0
		if plan.HeaderPlanning != nil {
			ordinal = len(plan.HeaderPlanning.Queries)
		}
		plan.headerPlanningQueryStarts++
		var metadata *gotoolprofile.MetadataProof
		err = journal.run(candidate.exactKey(), "ordinary_header_query", fmt.Sprintf("%s/%s/%d", request.Target, assembly, ordinal), func() error {
			var err error
			metadata, err = captureDiscoveryGeneratedHeaderQuery(ctx, queryPlan, download, profile, tags, group, queryDir, queryEnv, translator, ordinal)
			return err
		})
		if err != nil {
			return nil, fmt.Errorf("actual native header planning query: %w", err)
		}
		if len(metadata.Headers) != 1 {
			return nil, fmt.Errorf("native header planning lacks its unique actual query")
		}
		// Do not publish an unclosed query into the portable role. Independently
		// replay a private candidate first; rejected domains retain all CPUs.
		role := &discoveryCPPHeaderPlanning{Protocol: discoveryCPPHeaderPlanningProtocol, Rules: rules,
			Sources: make(map[string]string)}
		if plan.HeaderPlanning != nil {
			role.Queries = append(role.Queries, plan.HeaderPlanning.Queries...)
			for name, text := range plan.HeaderPlanning.Sources {
				role.Sources[name] = text
			}
			if len(plan.HeaderPlanning.ImportedSources) != 0 {
				role.ImportedSources = make(map[string]string, len(plan.HeaderPlanning.ImportedSources))
			}
			for name, text := range plan.HeaderPlanning.ImportedSources {
				role.ImportedSources[name] = text
			}
		}
		for name, digest := range metadata.Headers[0].CompiledGoSHA256 {
			if !ordinarySelectionLocalPath(name) || !strings.HasSuffix(name, ".go") {
				return nil, fmt.Errorf("native planning compiler source has an unbound role")
			}
			file := filepath.Join(download.Dir, filepath.FromSlash(name))
			if err := discoveryCPPRegularSource(download.Dir, file); err != nil {
				return nil, err
			}
			text, err := readDiscoveryHeaderPlanningSource(file)
			if err != nil || discoveryFeatureBytesSHA256(text) != digest {
				return nil, fmt.Errorf("native planning source differs from selected original compiler bytes: %v", err)
			}
			if before, present := role.Sources[name]; present && before != string(text) {
				return nil, fmt.Errorf("native planning original source changed between queries")
			}
			role.Sources[name] = string(text)
		}
		imports, err := captureDiscoveryPlanningImports(role, queryPlan, metadata.Headers[0], module, download.Dir)
		if err != nil {
			return nil, err
		}
		if err := validateDiscoveryPlanningSources(role); err != nil {
			return nil, err
		}
		inventory := newDiscoveryFeatureInventory()
		for id, observed := range plan.headerPlanningInventory.Observations {
			inventory.Observations[id] = observed // Already privately frozen by registration.
		}
		references, err := registerDiscoveryFeatureProfiles(inventory, []discoveryFeatureProfile{profile})
		if err != nil {
			return nil, err
		}
		role.Queries = append(role.Queries, discoveryCPPHeaderPlanningQuery{
			Assembly: assembly, Profile: references[0], BuildTags: append([]string(nil), tags...), Metadata: metadata,
			ImportedGoSHA256: imports,
		})
		copy := *plan
		copy.HeaderPlanning, copy.headerPlanningInventory = role, inventory
		// Source capture ran against a temporary selection plan. Successful
		// header replay must carry its independently owned dependencies into
		// the surviving plan, including query-only imports/assets. Keep the
		// publication atomic and never share a mutable guard slice backing.
		copy.ordinaryDependencyContext = ctx
		copy.ordinaryDependencyGuards = append([]discoveryOrdinaryDependencyGuard(nil), plan.ordinaryDependencyGuards...)
		for _, source := range queryPlan.ordinaryDependencyGuards {
			source.Context = ctx
			if err := retainDiscoveryOrdinaryDependencyGuard(&copy, source); err != nil {
				return nil, err
			}
		}
		header, err = replayDiscoveryPlanningHeader(&copy, request, assembly, tags)
		if err != nil {
			if gotoolprofile.NativeHeaderSourceDomainUnsupported(err) {
				return nil, &discoveryHeaderPlanningUnsupported{err.Error()}
			}
			return nil, err
		}
		plan.HeaderPlanning, plan.headerPlanningInventory = role, inventory
		plan.ordinaryDependencyContext, plan.ordinaryDependencyGuards = copy.ordinaryDependencyContext, copy.ordinaryDependencyGuards
		return header, nil
	}
	return nil
}

// This is the independently owned query main, never the downloaded module.
// A minor-only go directive can be rewritten by cmd/go when an exact dependency
// requires the running SDK's patch release, invalidating the frozen workspace.
// Preserve the full observed SDK version before capture; the ordinary profile
// observation still authenticates that version and original dependency roles.
func discoveryHeaderQueryGoMod(source, goVersion string) (string, error) {
	version := strings.TrimPrefix(goVersion, "go")
	if !strings.HasPrefix(goVersion, "go1.") || strings.ContainsAny(version, "-+") || !semver.IsValid("v"+version) {
		return "", fmt.Errorf("planning query lacks a stable Go SDK version")
	}
	module, err := modfile.Parse("go.mod", []byte(source), nil)
	if err != nil {
		return "", err
	}
	if err := module.AddGoStmt(version); err != nil {
		return "", err
	}
	data, err := module.Format()
	return string(data), err
}

func readDiscoveryHeaderPlanningSource(name string) ([]byte, error) {
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	return readDiscoveryHeaderPlanningInput(file)
}

func readDiscoveryHeaderPlanningInput(file io.ReadCloser) (data []byte, result error) {
	defer func() {
		if err := file.Close(); err != nil {
			data, result = nil, errors.Join(result, err)
		}
	}()
	data, err := io.ReadAll(io.LimitReader(file, 2<<20+1))
	if err != nil {
		return nil, fmt.Errorf("planning source is unreadable: %w", err)
	}
	if len(data) > 2<<20 {
		return nil, fmt.Errorf("planning source exceeds its byte bound")
	}
	return data, nil
}

type discoveryHeaderQueryWorkspace struct {
	directory string
	physical  string
	dirs      map[string]os.FileInfo
	module    os.FileInfo
	goMod     string
}

func captureDiscoveryHeaderQueryWorkspace(directory, goMod string) (*discoveryHeaderQueryWorkspace, error) {
	physical, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return nil, err
	}
	guard := &discoveryHeaderQueryWorkspace{directory: directory, physical: physical, dirs: make(map[string]os.FileInfo), goMod: goMod}
	for current := physical; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() {
			return nil, fmt.Errorf("planning query workspace has an unbound directory")
		}
		guard.dirs[current] = info
		if filepath.Dir(current) == current {
			break
		}
	}
	guard.module, err = os.Lstat(filepath.Join(directory, "go.mod"))
	if err != nil || !guard.module.Mode().IsRegular() {
		return nil, fmt.Errorf("planning query workspace lacks its original module file")
	}
	return guard, guard.verify()
}

func (guard *discoveryHeaderQueryWorkspace) verify() error {
	physical, err := filepath.EvalSymlinks(guard.directory)
	if err != nil || physical != guard.physical {
		return fmt.Errorf("planning query workspace alias changed")
	}
	for name, before := range guard.dirs {
		after, err := os.Lstat(name)
		if err != nil || !after.IsDir() || !os.SameFile(before, after) {
			return fmt.Errorf("planning query workspace directory identity changed")
		}
	}
	name := filepath.Join(guard.directory, "go.mod")
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(guard.module, info) {
		return fmt.Errorf("planning query module identity changed")
	}
	data, err := readDiscoveryHeaderPlanningSource(name)
	if err != nil {
		return fmt.Errorf("read planning query module: %w", err)
	}
	if string(data) != guard.goMod {
		return fmt.Errorf("planning query module bytes changed")
	}
	return nil
}

func replayDiscoveryPlanningHeader(plan *discoveryOrdinarySelectionPlan, request discoveryFeatureProfileRequest, assembly string, tags []string) (*gotoolprofile.GeneratedHeaderProof, error) {
	copy := *plan
	copy.headerPlanningCapture = nil
	return discoveryPlanningHeader(&copy, request, assembly, tags)
}
