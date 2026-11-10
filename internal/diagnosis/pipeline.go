package diagnosis

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/causent/malenia/internal/cache"
	"github.com/causent/malenia/internal/domain"
	"github.com/causent/malenia/internal/history"
	"github.com/causent/malenia/internal/investigation"
	"github.com/causent/malenia/internal/localization"
	"github.com/causent/malenia/internal/observability"
	"github.com/causent/malenia/internal/reasoning"
	"github.com/causent/malenia/internal/relationships"
	programrepo "github.com/causent/malenia/internal/repository"
)

// persistArchitecture runs the staged repository-intelligence and diagnosis path.
// Stages publish a preliminary finding as soon as candidates and hypotheses exist,
// then optionally continue into adaptive deep investigation.
func (d *Diagnoser) persistArchitecture(ctx context.Context, report *Report, workspace string, baseline Baseline, env Environment, loc Localization, evidenceOnly bool) error {
	if d.metrics == nil {
		d.metrics = observability.NewMetrics(report.InvestigationID)
	}
	if d.cfg.Store == nil {
		return d.runStagedIntelligence(ctx, report, workspace, baseline, env, loc, false, evidenceOnly)
	}
	return d.runStagedIntelligence(ctx, report, workspace, baseline, env, loc, true, evidenceOnly)
}

func (d *Diagnoser) runStagedIntelligence(ctx context.Context, report *Report, workspace string, baseline Baseline, env Environment, loc Localization, persist, evidenceOnly bool) error {
	repoID := "local:" + d.cfg.RepoPath
	revisionID := "revision:" + env.HeadCommit
	provider := d.cfg.CIProvider
	if provider == "" {
		provider = "local"
	}
	externalExecutionID := d.cfg.ExternalExecutionID
	if externalExecutionID == "" {
		externalExecutionID = report.InvestigationID
	}
	pullRequestID := ""
	if persist {
		if err := d.cfg.Store.SaveRepository(domain.Repository{ID: repoID, Provider: provider, CanonicalID: d.cfg.RepoPath, Name: d.cfg.RepoPath}); err != nil {
			return err
		}
		if err := d.cfg.Store.SaveRevision(domain.Revision{ID: revisionID, RepositoryID: repoID, CommitSHA: env.HeadCommit, CreatedAt: report.CreatedAt}); err != nil {
			return err
		}
		if d.cfg.PullRequestID != "" {
			pullRequestID = "pr:" + d.cfg.PullRequestID
			baseRevisionID := ""
			if d.cfg.BaseRef != "" {
				if base := stringsTrim(gitOutput(d.cfg.RepoPath, "rev-parse", d.cfg.BaseRef)); base != "" {
					baseRevisionID = "revision:" + base
					_ = d.cfg.Store.SaveRevision(domain.Revision{ID: baseRevisionID, RepositoryID: repoID, CommitSHA: base, CreatedAt: report.CreatedAt})
				}
			}
			if err := d.cfg.Store.SavePullRequest(domain.PullRequest{ID: pullRequestID, RepositoryID: repoID, ExternalPRID: d.cfg.PullRequestID, BaseRevisionID: baseRevisionID, HeadRevisionID: revisionID, Status: "open", Metadata: map[string]string{"source_url": d.cfg.SourceURL}}); err != nil {
				return err
			}
		}
		if err := d.persistReportEvidence(report); err != nil {
			return err
		}
	}

	var artifactCache *cache.FSCache
	var err error
	if !evidenceOnly {
		artifactCache, err = d.openArtifactCache()
		if err != nil {
			report.Uncertainty = append(report.Uncertainty, "artifact cache unavailable: "+err.Error())
		}

		overview, overviewErr := d.stageOverview(ctx, report, workspace, repoID, revisionID, env.HeadCommit, artifactCache)
		if overviewErr != nil {
			return overviewErr
		}
		report.Overview = &overview
	} else {
		overviewStage := d.metrics.Begin(observability.StageRepositoryOverview)
		overviewStage.Meta("mode", "skipped")
		overviewStage.Meta("reason", "evidence_only")
		overviewStage.Done("skipped", nil)
		report.IndexingMode = "skipped_evidence_only"
		report.Uncertainty = append(report.Uncertainty, "repository overview and indexing were deferred because source-level analysis was not justified")
	}

	executionID := "execution:" + report.InvestigationID
	if persist {
		if err := d.cfg.Store.SaveCIExecution(domain.CIExecution{ID: executionID, RepositoryID: repoID, PullRequestID: pullRequestID, HeadRevisionID: revisionID, Provider: provider, ExternalExecutionID: externalExecutionID, Status: string(report.Classification), StartedAt: &baseline.StartedAt, CompletedAt: &baseline.FinishedAt, RawMetadata: map[string]string{"source_url": d.cfg.SourceURL}}); err != nil {
			return err
		}
	}

	stage := d.metrics.Begin(observability.StageFailureIngestion)
	failures, err := d.persistFailureEpisodes(report, executionID, baseline)
	if err != nil {
		stage.Done("failed", err)
		return err
	}
	report.FailureEpisodes = failures
	for _, item := range report.Evidence {
		if !isCIEvidenceKind(item.Kind) {
			continue
		}
		for _, race := range parseRaceReports(item.Detail) {
			race.EvidenceIDs = []string{item.ID}
			report.RaceReports = append(report.RaceReports, race)
		}
	}
	stage.Count("episodes", len(failures))
	stage.Done("completed", nil)

	var snapshot programrepo.Snapshot
	if !evidenceOnly {
		var indexMode string
		snapshot, indexMode, err = d.stageIndex(ctx, report, workspace, repoID, revisionID, env.HeadCommit, loc, artifactCache)
		if err != nil {
			return err
		}
		d.snapshot = &snapshot
		report.IndexingMode = indexMode
	} else {
		indexStage := d.metrics.Begin(observability.StageIndexing)
		indexStage.Meta("mode", "skipped")
		indexStage.Meta("reason", "evidence_only")
		indexStage.Done("skipped", nil)
	}
	if persist {
		persistStage := d.metrics.Begin(observability.StagePersistence)
		persistStage.Meta("mode", "batched_snapshot")
		if err := d.cfg.Store.SaveProgramNodes(snapshot.Nodes); err != nil {
			persistStage.Done("failed", err)
			return err
		}
		if err := d.cfg.Store.SaveRelationships(snapshot.Relationships); err != nil {
			persistStage.Done("failed", err)
			return err
		}
		persistStage.Count("nodes", len(snapshot.Nodes))
		persistStage.Count("relationships", len(snapshot.Relationships))
		persistStage.Done("completed", nil)
	}
	targetedEvidence := report.NormalizedEvidence != nil
	if !evidenceOnly && d.cfg.BaseRef != "" && !targetedEvidence {
		deltas, deltaEvidence, deltaErr := d.stageDeltas(ctx, workspace, repoID, revisionID, snapshot)
		if deltaErr != nil {
			report.Uncertainty = append(report.Uncertainty, "revision delta analysis incomplete: "+deltaErr.Error())
			report.Partial = true
		} else if len(deltas) > 0 {
			report.Deltas = deltas
			report.Evidence = append(report.Evidence, deltaEvidence)
			if persist {
				if err := d.cfg.Store.SaveEvidence(domain.Evidence{ID: domain.ID(deltaEvidence.ID), InvestigationID: domain.ID(report.InvestigationID), Type: domain.EvidenceType(deltaEvidence.Kind), Source: deltaEvidence.Source, Timestamp: report.CreatedAt, ContentRef: deltaEvidence.Kind, Digest: deltaEvidence.Digest, Payload: deltaEvidence.Detail, Provenance: deltaEvidence.Provenance}); err != nil {
					return err
				}
				for _, delta := range deltas {
					if err := d.cfg.Store.SaveCodeDelta(delta); err != nil {
						return err
					}
				}
			}
		}
	}

	frames := architectureFrames(baseline, failures, report.Evidence)
	frameEvidence := observedFrameEvidence(frames)
	report.Evidence = append(report.Evidence, frameEvidence...)
	for i := range frames {
		if i < len(frameEvidence) {
			frames[i].EvidenceIDs = []domain.ID{domain.ID(frameEvidence[i].ID)}
		}
	}
	var evidenceIDs []domain.ID
	for _, e := range report.Evidence {
		evidenceIDs = append(evidenceIDs, domain.ID(e.ID))
	}
	failureIDs := make([]string, 0, len(failures))
	for _, failure := range failures {
		failureIDs = append(failureIDs, failure.ID)
	}
	changed := map[string]bool{}
	for _, path := range loc.LikelyFiles {
		for i := range snapshot.Nodes {
			if snapshot.Nodes[i].FilePath == path {
				snapshot.Nodes[i].Changed = true
				changed[snapshot.Nodes[i].Identity] = true
			}
		}
	}
	for _, delta := range report.Deltas {
		changed[delta.SymbolIdentity] = true
	}

	candStage := d.metrics.Begin(observability.StageCandidateGeneration)
	var candidates []domain.CandidateLocation
	var relations []domain.Relationship
	maxCandidates := 100
	if report.NormalizedEvidence != nil || report.Baseline.Source == "ci_artifact" {
		maxCandidates = 25
	}
	input := localization.Input{InvestigationID: domain.ID(report.InvestigationID), RepositoryID: repoID, RevisionID: revisionID, FailureIDs: failureIDs, EvidenceIDs: evidenceIDs, StackFrames: frames, FailureText: failureText(baseline, report.Evidence), ChangedIdentities: changed, MaxDepth: 2, MaxCandidates: maxCandidates}
	if evidenceOnly {
		candidates, relations = localization.GenerateObserved(frames, input)
	} else {
		candidates, relations = localization.Generate(snapshot, input)
	}
	if !evidenceOnly {
		var sourceEvidence []EvidenceItem
		candidates, sourceEvidence = sourceEvidenceForCandidates(workspace, env.HeadCommit, candidates)
		report.Evidence = append(report.Evidence, sourceEvidence...)
		if persist {
			for _, item := range sourceEvidence {
				if err := d.cfg.Store.SaveEvidence(domain.Evidence{ID: domain.ID(item.ID), InvestigationID: domain.ID(report.InvestigationID), Type: domain.EvidenceType(item.Kind), Source: item.Source, Timestamp: report.CreatedAt, ContentRef: item.Kind, Digest: item.Digest, Payload: item.Detail, Provenance: item.Provenance}); err != nil {
					return err
				}
			}
		}
	}
	for _, candidate := range candidates {
		for _, delta := range report.Deltas {
			if candidate.Location.SymbolIdentity != delta.SymbolIdentity && candidate.Location.FilePath != delta.FilePath {
				continue
			}
			relations = append(relations, domain.Relationship{
				ID: "candidate:" + candidate.ID + ":delta:" + delta.ID, InvestigationID: domain.ID(report.InvestigationID),
				SourceType: "candidate_location", SourceID: candidate.ID, TargetType: "code_delta", TargetID: delta.ID,
				Type: "CHANGED_BY_PR", RevisionID: delta.HeadRevisionID, EvidenceIDs: []domain.ID{delta.EvidenceID},
			})
		}
	}
	paths, pathEvidence := buildExecutionPaths(domain.ID(report.InvestigationID), snapshot, candidates, failureText(baseline, report.Evidence), failureIDs, evidenceIDs)
	report.ExecutionPaths = paths
	report.Evidence = append(report.Evidence, pathEvidence...)
	if persist {
		for _, path := range paths {
			if err := d.cfg.Store.SaveExecutionPath(path); err != nil {
				return err
			}
		}
		for _, item := range pathEvidence {
			if err := d.cfg.Store.SaveEvidence(domain.Evidence{ID: domain.ID(item.ID), InvestigationID: domain.ID(report.InvestigationID), Type: domain.EvidenceType(item.Kind), Source: item.Source, Timestamp: report.CreatedAt, ContentRef: item.Kind, Digest: item.Digest, Payload: item.Detail, Provenance: item.Provenance}); err != nil {
				return err
			}
		}
	}
	report.Candidates = candidates
	report.Relationships = relations
	candStage.Count("candidates", len(candidates))
	candStage.Done("completed", nil)
	if persist {
		for _, c := range candidates {
			if err := d.cfg.Store.SaveCodeLocation(c.Location); err != nil {
				return err
			}
			if err := d.cfg.Store.SaveCandidate(c); err != nil {
				return err
			}
		}
		if err := d.cfg.Store.SaveRelationships(relations); err != nil {
			return err
		}
	}

	groupStage := d.metrics.Begin(observability.StageFailureGrouping)
	discovery := relationships.Discover(domain.ID(report.InvestigationID), failures, candidates, relations)
	report.FailureGroups = discovery.Groups
	groupStage.Count("groups", len(discovery.Groups))
	groupStage.Done("completed", nil)
	if persist {
		for _, group := range discovery.Groups {
			if err := d.cfg.Store.SaveFailureGroup(group); err != nil {
				return err
			}
		}
		for _, rel := range discovery.Relationships {
			if err := d.cfg.Store.SaveRelationship(rel); err != nil {
				return err
			}
			report.Relationships = append(report.Relationships, rel)
		}
	} else {
		report.Relationships = append(report.Relationships, discovery.Relationships...)
	}

	if persist {
		if !evidenceOnly {
			historical, histErr := history.Discover(d.cfg.Store, history.Input{InvestigationID: domain.ID(report.InvestigationID), RepositoryID: repoID, RevisionID: revisionID, Failures: failures, Candidates: candidates, EvidenceIDs: evidenceIDs})
			if histErr != nil {
				return histErr
			}
			report.HistoricalContext = historical.References
			if len(historical.Evidence) > 0 {
				for _, evidence := range historical.Evidence {
					if err := d.cfg.Store.SaveEvidence(evidence); err != nil {
						return err
					}
					report.Evidence = append(report.Evidence, EvidenceItem{ID: string(evidence.ID), Kind: string(evidence.Type), Source: evidence.Source, Digest: evidence.Digest, Detail: evidence.Payload})
				}
				report.Candidates = localization.ApplyHistoricalEvidence(report.Candidates, evidenceIDsOfHistorical(historical.Evidence))
				for _, candidate := range report.Candidates {
					if err := d.cfg.Store.SaveCandidate(candidate); err != nil {
						return err
					}
				}
				candidates = report.Candidates
			}
			for _, rel := range historical.Relationships {
				if err := d.cfg.Store.SaveRelationship(rel); err != nil {
					return err
				}
				report.Relationships = append(report.Relationships, rel)
			}
			for _, stageName := range []string{"AnalyzeRepository", "GenerateCandidates", "DiscoverRelationships"} {
				activity := investigation.NewActivity(domain.ID(report.InvestigationID), "activity:"+report.InvestigationID+":"+stageName, stageName, nil, evidenceIDsToStrings(evidenceIDs))
				activity = investigation.Complete(activity, []string{"report:" + report.InvestigationID + ":" + stageName})
				if err := d.cfg.Store.SaveActivity(activity); err != nil {
					return err
				}
			}
		}
	}

	hypStage := d.metrics.Begin(observability.StageHypothesisGeneration)
	hypothesisCandidates := candidates
	if report.NormalizedEvidence != nil || report.Baseline.Source == "ci_artifact" {
		hypothesisCandidates = make([]domain.CandidateLocation, 0, len(candidates))
		for _, candidate := range candidates {
			if candidate.Score.ExecutionRelevance > 0 || candidate.Score.BehaviouralRelevance > 0 {
				hypothesisCandidates = append(hypothesisCandidates, candidate)
			}
		}
	}
	report.Hypotheses = reasoning.Generate(domain.ID(report.InvestigationID), discovery.Groups, hypothesisCandidates)
	evidenceMap := map[domain.ID]domain.Evidence{}
	for _, item := range report.Evidence {
		evidenceMap[domain.ID(item.ID)] = domain.Evidence{ID: domain.ID(item.ID), InvestigationID: domain.ID(report.InvestigationID), Type: domain.EvidenceType(item.Kind)}
	}
	candidateMap := map[string]domain.CandidateLocation{}
	for _, candidate := range candidates {
		candidateMap[candidate.ID] = candidate
	}
	hypothesisMap := map[domain.ID]domain.Hypothesis{}
	for index, hypothesis := range report.Hypotheses {
		assessed := reasoning.Assess(hypothesis, evidenceMap, nil, nil).Hypothesis
		report.Hypotheses[index] = assessed
		hypothesisMap[assessed.ID] = assessed
		if persist {
			if err := d.cfg.Store.SaveHypothesis(assessed); err != nil {
				return err
			}
			if err := d.cfg.Store.SaveHypothesisHistory(domain.HypothesisHistory{ID: domain.NewID(), HypothesisID: assessed.ID, InvestigationID: assessed.InvestigationID, PreviousStatus: domain.HypProposed, NextStatus: assessed.Status, Evaluation: "assessment from persisted evidence", CreatedAt: time.Now().UTC()}); err != nil {
				return err
			}
		}
	}
	hypStage.Count("hypotheses", len(report.Hypotheses))
	hypStage.Done("completed", nil)

	revisions := map[string]bool{revisionID: true}
	for _, candidate := range candidates {
		revisions[candidate.Location.RevisionID] = true
	}
	for _, hypothesis := range report.Hypotheses {
		finding := domain.DiagnosticFinding{ID: "finding:" + string(hypothesis.ID), InvestigationID: hypothesis.InvestigationID, Kind: "hypothesis_assessment", Statement: hypothesis.Statement, HypothesisID: hypothesis.ID, EvidenceIDs: hypothesis.SupportingEvidenceIDs, CandidateIDs: hypothesis.CandidateLocationIDs, Status: string(hypothesis.Status), Uncertainty: hypothesis.MissingEvidence, CreatedAt: time.Now().UTC()}
		validation := reasoning.ValidateFinding(finding, domain.ID(report.InvestigationID), evidenceMap, hypothesisMap, candidateMap, revisions)
		if !validation.Valid {
			finding.Status = "unresolved"
			finding.Uncertainty = append(finding.Uncertainty, validation.Reasons...)
		}
		report.Findings = append(report.Findings, finding)
		if persist {
			if err := d.cfg.Store.SaveFinding(finding); err != nil {
				return err
			}
			if err := d.cfg.Store.SaveClaimValidation(domain.ClaimValidation{ClaimID: finding.ID, Valid: validation.Valid, Reasons: validation.Reasons, ValidatedAt: validation.ValidatedAt}); err != nil {
				return err
			}
		}
	}
	if len(candidates) > 0 {
		statement := fmt.Sprintf("Candidate locations were ranked from execution and repository evidence; top candidate is %s", candidates[0].Location.SymbolIdentity)
		kind := "candidate_localization"
		status := "potential"
		uncertainty := []string{"candidate ranking is not a causal proof"}
		if evidenceOnly {
			statement = fmt.Sprintf("An observed location was extracted from execution output: %s. Its relationship to the underlying failure has not been verified against source code.", candidates[0].Location.FilePath)
			kind = "observed_location"
			status = "observed"
			uncertainty = []string{"source code was not inspected", "the observed location is not a verified fault site"}
		}
		finding := domain.DiagnosticFinding{ID: "finding:" + report.InvestigationID, InvestigationID: domain.ID(report.InvestigationID), Kind: kind, Statement: statement, EvidenceIDs: candidates[0].SupportingEvidenceIDs, CandidateIDs: []string{candidates[0].ID}, Status: status, Uncertainty: uncertainty, CreatedAt: time.Now().UTC()}
		report.Findings = append(report.Findings, finding)
		if persist {
			if err := d.cfg.Store.SaveFinding(finding); err != nil {
				return err
			}
		}
	}

	prelim := d.metrics.Begin(observability.StagePreliminaryDiagnosis)
	d.publishPreliminary(report)
	prelim.Done("completed", nil)
	d.metrics.MarkFirstFinding()
	d.emit(EventPreliminaryDiagnosis, domain.StatusFormingHypotheses, "preliminary diagnosis available")
	d.refreshProgressiveBundle(report)
	return nil
}

func (d *Diagnoser) stageOverview(ctx context.Context, report *Report, workspace, repoID, revisionID, commitSHA string, artifactCache *cache.FSCache) (programrepo.Overview, error) {
	slog.Info("diagnosis stage started", "stage", "repository_overview", "investigation_id", report.InvestigationID)
	if report.NormalizedEvidence != nil || report.Baseline.Source == "ci_artifact" {
		stage := d.metrics.Begin(observability.StageRepositoryOverview)
		stage.Meta("mode", "focused")
		overview := focusedOverview(repoID, revisionID, commitSHA, report.Localization.LikelyFiles)
		stage.Count("files", sumCounts(overview.FileCounts))
		stage.Count("languages", len(overview.Languages))
		stage.Done("completed", nil)
		slog.Info("diagnosis stage completed", "stage", "repository_overview", "mode", "focused", "selected_paths", len(report.Localization.LikelyFiles))
		report.CoverageNotes = append(report.CoverageNotes, "repository overview is focused on CI-selected paths; broad metadata scan is deferred")
		return overview, nil
	}
	stage := d.metrics.Begin(observability.StageRepositoryOverview)
	key := cache.Key{RepositoryID: repoID, CommitSHA: commitSHA, AnalyzerVersion: cache.AnalyzerVersion, ArtifactType: cache.ArtifactOverview, ArtifactID: "overview"}
	var overview programrepo.Overview
	if artifactCache != nil {
		if err := artifactCache.Get(key, &overview); err == nil {
			d.metrics.RecordCacheHit()
			stage.Meta("cache", "hit")
			stage.Count("files", sumCounts(overview.FileCounts))
			stage.Done("completed", nil)
			return overview, nil
		} else if !errors.Is(err, cache.ErrMiss) && !errors.Is(err, cache.ErrDisabled) && !errors.Is(err, cache.ErrCorrupt) {
			stage.Done("failed", err)
			return overview, err
		}
		d.metrics.RecordCacheMiss()
		stage.Meta("cache", "miss")
	}
	overview, err := programrepo.BuildOverview(ctx, workspace, repoID, revisionID, commitSHA)
	if err != nil {
		stage.Done("failed", err)
		return overview, err
	}
	if artifactCache != nil {
		_ = artifactCache.Put(key, overview)
	}
	stage.Count("files", sumCounts(overview.FileCounts))
	stage.Count("languages", len(overview.Languages))
	stage.Done("completed", nil)
	_ = report
	return overview, nil
}

func focusedOverview(repoID, revisionID, commitSHA string, paths []string) programrepo.Overview {
	counts := map[string]int{}
	langs := map[string]bool{}
	for _, path := range paths {
		var lang string
		switch strings.ToLower(filepath.Ext(path)) {
		case ".go":
			lang = "go"
		case ".py":
			lang = "python"
		case ".js", ".jsx", ".mjs", ".ts", ".tsx":
			lang = "javascript"
		case ".rs":
			lang = "rust"
		}
		if lang != "" {
			counts[lang]++
			langs[lang] = true
		}
	}
	var languages []string
	for lang := range langs {
		languages = append(languages, lang)
	}
	sort.Strings(languages)
	return programrepo.Overview{
		RepositoryID: repoID, RevisionID: revisionID, CommitSHA: commitSHA,
		Languages: languages, FileCounts: counts, GeneratedAt: time.Now().UTC(),
		CoverageNotes: []string{"focused overview is not exhaustive; missing languages and files are unresolved"},
		Metadata:      map[string]string{"mode": "focused", "selected_paths": fmt.Sprint(len(paths))},
	}
}

func (d *Diagnoser) stageIndex(ctx context.Context, report *Report, workspace, repoID, revisionID, commitSHA string, loc Localization, artifactCache *cache.FSCache) (programrepo.Snapshot, string, error) {
	slog.Info("diagnosis stage started", "stage", "indexing", "investigation_id", report.InvestigationID)
	key := cache.Key{RepositoryID: repoID, CommitSHA: commitSHA, AnalyzerVersion: cache.AnalyzerVersion, ArtifactType: cache.ArtifactSnapshot, ArtifactID: "snapshot"}
	if artifactCache != nil {
		var cached programrepo.Snapshot
		if err := artifactCache.Get(key, &cached); err == nil {
			d.metrics.RecordCacheHit()
			stage := d.metrics.Begin(observability.StageIndexing)
			stage.Meta("cache", "hit")
			stage.Meta("mode", "cached")
			stage.Count("files", countSnapshotFiles(cached))
			stage.Count("symbols", countSnapshotSymbols(cached))
			stage.Done("completed", nil)
			return cached, "cached", nil
		} else if errors.Is(err, cache.ErrMiss) || errors.Is(err, cache.ErrCorrupt) {
			d.metrics.RecordCacheMiss()
		} else if !errors.Is(err, cache.ErrDisabled) {
			return programrepo.Snapshot{}, "", err
		}
	}

	analyzer := programrepo.Analyzer{}
	// Targeted indexing is for externally observed CI failures. Ordinary local
	// reproduction still uses the complete snapshot because its localization
	// and adaptive stages already provide an explicit repository scope.
	if report.NormalizedEvidence != nil || report.Baseline.Source == "ci_artifact" {
		if targeted := expandTargetPaths(workspace, loc.LikelyFiles, 80); len(targeted) > 0 {
			stage := d.metrics.Begin(observability.StageIndexing)
			stage.Meta("mode", "targeted")
			snapshot, err := analyzer.AnalyzePaths(ctx, workspace, repoID, revisionID, commitSHA, targeted)
			if err != nil {
				stage.Done("failed", err)
				return snapshot, "", err
			}
			stage.Count("files", countSnapshotFiles(snapshot))
			stage.Count("symbols", countSnapshotSymbols(snapshot))
			stage.Count("requested_files", len(targeted))
			stage.Done("completed", nil)
			report.CoverageNotes = append(report.CoverageNotes,
				"targeted indexing selected CI-reported and PR-relevant files before broader expansion",
				"snapshot coverage is intentionally bounded; absent files are unresolved, not negative evidence")
			return snapshot, "targeted", nil
		}
		stage := d.metrics.Begin(observability.StageIndexing)
		stage.Meta("mode", "targeted-empty")
		stage.Done("incomplete", nil)
		report.CoverageNotes = append(report.CoverageNotes, "no usable source paths were extracted from CI evidence; broad indexing was refused")
		slog.Warn("targeted indexing had no usable paths; broad scan refused", "investigation_id", report.InvestigationID)
		return programrepo.Snapshot{RepositoryID: repoID, RevisionID: revisionID, CommitSHA: commitSHA}, "targeted-empty", nil
	}
	baseRef := d.cfg.BaseRef
	if baseRef != "" && artifactCache != nil {
		baseSHA := stringsTrim(gitOutput(d.cfg.RepoPath, "rev-parse", baseRef))
		if baseSHA != "" {
			baseKey := cache.Key{RepositoryID: repoID, CommitSHA: baseSHA, AnalyzerVersion: cache.AnalyzerVersion, ArtifactType: cache.ArtifactSnapshot, ArtifactID: "snapshot"}
			var base programrepo.Snapshot
			if err := artifactCache.Get(baseKey, &base); err == nil {
				d.metrics.RecordCacheHit()
				changes, diffErr := programrepo.DiffFiles(ctx, workspace, baseSHA, commitSHA)
				if diffErr == nil {
					stage := d.metrics.Begin(observability.StageIncrementalIndexing)
					inc, incErr := analyzer.AnalyzeIncremental(ctx, workspace, repoID, revisionID, commitSHA, base, changes)
					if incErr != nil {
						stage.Done("failed", incErr)
						return programrepo.Snapshot{}, "", incErr
					}
					stage.Count("files", countSnapshotFiles(inc.Snapshot))
					stage.Count("symbols", countSnapshotSymbols(inc.Snapshot))
					stage.Count("reparsed", inc.ReparsedFiles)
					stage.Count("reused", inc.ReusedFiles)
					stage.Meta("mode", "incremental")
					stage.Done("completed", nil)
					report.CoverageNotes = append(report.CoverageNotes, inc.CoverageNotes...)
					_ = artifactCache.Put(key, inc.Snapshot)
					_ = loc
					return inc.Snapshot, "incremental", nil
				}
			} else if errors.Is(err, cache.ErrMiss) {
				d.metrics.RecordCacheMiss()
			}
		}
	}

	stage := d.metrics.Begin(observability.StageIndexing)
	stage.Meta("mode", "full")
	snapshot, err := analyzer.Analyze(ctx, workspace, repoID, revisionID, commitSHA)
	if err != nil {
		stage.Done("failed", err)
		return snapshot, "", err
	}
	stage.Count("files", countSnapshotFiles(snapshot))
	stage.Count("symbols", countSnapshotSymbols(snapshot))
	stage.Done("completed", nil)
	if artifactCache != nil {
		_ = artifactCache.Put(key, snapshot)
	}
	return snapshot, "full", nil
}

func boundedTargetPaths(paths []string, max int) []string {
	seen := map[string]bool{}
	var out []string
	for _, path := range paths {
		path = strings.TrimSpace(filepath.ToSlash(path))
		if path == "" || seen[path] || len(out) >= max {
			continue
		}
		seen[path] = true
		out = append(out, path)
	}
	return out
}

func expandTargetPaths(root string, paths []string, max int) []string {
	out := boundedTargetPaths(paths, max)
	seen := map[string]bool{}
	for _, path := range out {
		seen[path] = true
	}
	for _, path := range append([]string(nil), out...) {
		if len(out) >= max {
			break
		}
		dir := filepath.Dir(filepath.Join(root, filepath.FromSlash(path)))
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !isSourcePath(entry.Name()) {
				continue
			}
			rel, err := filepath.Rel(root, filepath.Join(dir, entry.Name()))
			if err != nil {
				continue
			}
			rel = filepath.ToSlash(rel)
			if !seen[rel] && len(out) < max {
				seen[rel] = true
				out = append(out, rel)
			}
		}
	}
	return out
}

func isSourcePath(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".go", ".py", ".js", ".jsx", ".mjs", ".ts", ".tsx", ".rs":
		return true
	default:
		return false
	}
}

func (d *Diagnoser) stageDeltas(ctx context.Context, workspace, repoID, headRevisionID string, head programrepo.Snapshot) ([]domain.CodeDelta, EvidenceItem, error) {
	baseSHA := stringsTrim(gitOutput(d.cfg.RepoPath, "rev-parse", d.cfg.BaseRef))
	if baseSHA == "" {
		return nil, EvidenceItem{}, fmt.Errorf("base revision %q could not be resolved", d.cfg.BaseRef)
	}
	var base programrepo.Snapshot
	err := d.workspaceAt(ctx, baseSHA, func(dir string) error {
		var analyzeErr error
		base, analyzeErr = (programrepo.Analyzer{}).Analyze(ctx, dir, repoID, "revision:"+baseSHA, baseSHA)
		return analyzeErr
	})
	if err != nil {
		return nil, EvidenceItem{}, err
	}
	added, removed, changed := programrepo.Compare(base, head)
	baseNodes := map[string]domain.ProgramNode{}
	headNodes := map[string]domain.ProgramNode{}
	for _, node := range base.Nodes {
		if node.Type != "File" {
			baseNodes[node.Identity] = node
		}
	}
	for _, node := range head.Nodes {
		if node.Type != "File" {
			headNodes[node.Identity] = node
		}
	}
	const evidenceID = "E-pr-delta"
	var deltas []domain.CodeDelta
	addDelta := func(identity, kind string) {
		node := headNodes[identity]
		baseNode := baseNodes[identity]
		if node.Identity == "" {
			node = baseNode
		}
		line := node.StartLine
		if kind == "removed" {
			line = baseNode.StartLine
		}
		deltas = append(deltas, domain.CodeDelta{
			ID: "delta:" + digestString(baseSHA+"\x00"+head.CommitSHA+"\x00"+kind+"\x00"+identity), RepositoryID: repoID,
			BaseRevisionID: "revision:" + baseSHA, HeadRevisionID: headRevisionID, Kind: kind,
			SymbolIdentity: identity, FilePath: node.FilePath, BaseStartLine: baseNode.StartLine, HeadStartLine: headNodes[identity].StartLine,
			EvidenceID: evidenceID, Summary: fmt.Sprintf("%s symbol %s (%s:%d)", kind, identity, node.FilePath, line),
		})
	}
	for _, identity := range added {
		addDelta(identity, "added")
	}
	for _, identity := range removed {
		addDelta(identity, "removed")
	}
	for _, identity := range changed {
		addDelta(identity, "modified")
	}
	if len(deltas) == 0 {
		return nil, EvidenceItem{}, nil
	}
	var detail strings.Builder
	for _, delta := range deltas {
		detail.WriteString(delta.Summary)
		detail.WriteByte('\n')
	}
	evidence := EvidenceItem{ID: evidenceID, Kind: "pr_delta", Source: "base/head repository graph comparison", Digest: digestString(detail.String()), Detail: detail.String(), Provenance: "deterministic comparison of indexed base and head revisions"}
	return deltas, evidence, nil
}

type graphPathState struct {
	nodeIDs []string
	relIDs  []string
}

func buildExecutionPaths(investigationID domain.ID, snapshot programrepo.Snapshot, candidates []domain.CandidateLocation, failureText string, failureIDs []string, evidenceIDs []domain.ID) ([]domain.ExecutionPath, []EvidenceItem) {
	nodes := map[string]domain.ProgramNode{}
	for _, node := range snapshot.Nodes {
		nodes[node.ID] = node
	}
	edges := map[string][]domain.Relationship{}
	for _, relation := range snapshot.Relationships {
		edges[relation.SourceID] = append(edges[relation.SourceID], relation)
	}
	targets := map[string]bool{}
	provenanceByNode := map[string]string{}
	for _, candidate := range candidates {
		const prefix = "candidate:"
		if strings.HasPrefix(candidate.ID, prefix) {
			nodeID := strings.TrimPrefix(candidate.ID, prefix)
			targets[nodeID] = true
			provenanceByNode[nodeID] = candidate.Location.Provenance
		}
	}
	var tests []domain.ProgramNode
	for _, node := range snapshot.Nodes {
		if node.Type == "Test" && (strings.Contains(failureText, node.Name) || strings.Contains(failureText, node.FilePath)) {
			tests = append(tests, node)
		}
	}
	var paths []domain.ExecutionPath
	seen := map[string]bool{}
	for _, test := range tests {
		queue := []graphPathState{{nodeIDs: []string{test.ID}}}
		for len(queue) > 0 && len(paths) < 20 {
			state := queue[0]
			queue = queue[1:]
			current := state.nodeIDs[len(state.nodeIDs)-1]
			if len(state.nodeIDs) > 1 && targets[current] {
				locations := make([]domain.CodeLocation, 0, len(state.nodeIDs))
				parts := make([]string, 0, len(state.nodeIDs))
				for _, nodeID := range state.nodeIDs {
					node := nodes[nodeID]
					provenance := provenanceByNode[node.ID]
					if provenance == "" && node.ID == test.ID {
						provenance = "package_association"
					}
					locations = append(locations, domain.CodeLocation{ID: "location:" + node.ID, RepositoryID: node.RepositoryID, RevisionID: node.RevisionID, FilePath: node.FilePath, SymbolIdentity: node.Identity, StartLine: node.StartLine, EndLine: node.EndLine, LocationType: node.Type, Provenance: provenance})
					parts = append(parts, node.FilePath+":"+node.Name)
				}
				pathKey := strings.Join(state.nodeIDs, ">")
				if !seen[pathKey] {
					seen[pathKey] = true
					path := domain.ExecutionPath{ID: "path:" + digestString(string(investigationID)+"\x00"+pathKey), InvestigationID: investigationID, FailureIDs: append([]string{}, failureIDs...), NodeIDs: append([]string{}, state.nodeIDs...), RelationshipIDs: append([]string{}, state.relIDs...), Locations: locations, EvidenceIDs: append([]domain.ID{}, evidenceIDs...), Status: "inferred_call_path", Summary: strings.Join(parts, " → ")}
					paths = append(paths, path)
				}
				continue
			}
			if len(state.relIDs) >= 4 {
				continue
			}
			for _, relation := range edges[current] {
				// Structural references, imports, and package proximity are not
				// execution edges. Only explicit test/call relationships may
				// participate in an inferred call path.
				if relation.Type != "TESTS" && relation.Type != "CALLS" {
					continue
				}
				if _, ok := nodes[relation.TargetID]; !ok {
					continue
				}
				already := false
				for _, nodeID := range state.nodeIDs {
					if nodeID == relation.TargetID {
						already = true
						break
					}
				}
				if already {
					continue
				}
				queue = append(queue, graphPathState{nodeIDs: append(append([]string{}, state.nodeIDs...), relation.TargetID), relIDs: append(append([]string{}, state.relIDs...), relation.ID)})
			}
		}
	}
	var evidence []EvidenceItem
	for _, path := range paths {
		evidence = append(evidence, EvidenceItem{ID: "E-" + path.ID, Kind: "execution_path", Source: "revision-scoped repository graph", Digest: digestString(path.Summary), Detail: path.Summary, Provenance: "deterministic graph traversal; structural path, not causal proof", Revision: snapshot.CommitSHA})
	}
	return paths, evidence
}

func (d *Diagnoser) openArtifactCache() (*cache.FSCache, error) {
	root := d.cfg.CacheDir
	if root == "" && d.cfg.RepoPath != "" {
		root = filepath.Join(d.cfg.RepoPath, ".malenia", "artifact-cache")
	}
	return cache.OpenFS(root)
}

func (d *Diagnoser) publishPreliminary(report *Report) {
	status := "preliminary"
	statement := "Preliminary diagnosis from failure evidence and repository localization"
	if len(report.FailureEpisodes) == 0 {
		statement = "No distinct failure episodes extracted yet"
		status = "insufficient_evidence"
	} else if len(report.Candidates) > 0 {
		statement = fmt.Sprintf("Preliminary: %d failure episode(s), %d group(s); leading candidate %s", len(report.FailureEpisodes), len(report.FailureGroups), report.Candidates[0].Location.SymbolIdentity)
	} else {
		statement = fmt.Sprintf("Preliminary: %d failure episode(s) observed; candidate localization incomplete", len(report.FailureEpisodes))
		status = "partial"
	}
	finding := domain.DiagnosticFinding{
		ID:              "finding:preliminary:" + report.InvestigationID,
		InvestigationID: domain.ID(report.InvestigationID),
		Kind:            "preliminary_diagnosis",
		Statement:       statement,
		Status:          status,
		Uncertainty:     []string{"preliminary findings are not confirmed root causes", "adaptive investigation may revise this report"},
		CreatedAt:       time.Now().UTC(),
	}
	if len(report.Candidates) > 0 {
		finding.CandidateIDs = []string{report.Candidates[0].ID}
		finding.EvidenceIDs = report.Candidates[0].SupportingEvidenceIDs
	}
	report.Preliminary = &finding
	// Keep progressive findings de-duplicated across refreshes.
	filtered := report.Findings[:0]
	for _, existing := range report.Findings {
		if existing.ID != finding.ID {
			filtered = append(filtered, existing)
		}
	}
	report.Findings = append(filtered, finding)
	if d.cfg.Store != nil {
		_ = d.cfg.Store.SaveFinding(finding)
	}
}

func (d *Diagnoser) refreshProgressiveBundle(report *Report) {
	if d.cfg.BundleDir == "" {
		return
	}
	path, err := WriteBundle(*report, d.events, d.cfg.BundleDir)
	if err != nil {
		report.Uncertainty = append(report.Uncertainty, "progressive bundle update failed: "+err.Error())
		return
	}
	report.BundlePath = path
	report.ReplayCommand = fmt.Sprintf("malenia replay %s", path)
}

func sumCounts(values map[string]int) int {
	total := 0
	for _, n := range values {
		total += n
	}
	return total
}

func countSnapshotFiles(s programrepo.Snapshot) int {
	n := 0
	for _, node := range s.Nodes {
		if node.Type == "File" {
			n++
		}
	}
	return n
}

func countSnapshotSymbols(s programrepo.Snapshot) int {
	n := 0
	for _, node := range s.Nodes {
		switch node.Type {
		case "Function", "Method", "Test", "Class":
			n++
		}
	}
	return n
}

func stringsTrim(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\n' || s[0] == '\t' || s[0] == '\r') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\n' || s[len(s)-1] == '\t' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
