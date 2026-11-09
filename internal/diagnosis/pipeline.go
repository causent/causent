package diagnosis

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
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
func (d *Diagnoser) persistArchitecture(ctx context.Context, report *Report, workspace string, baseline Baseline, env Environment, loc Localization) error {
	if d.metrics == nil {
		d.metrics = observability.NewMetrics(report.InvestigationID)
	}
	if d.cfg.Store == nil {
		// Architecture persistence requires a store, but overview/indexing still
		// run so reports can carry structural context without SQLite.
		return d.runStagedIntelligence(ctx, report, workspace, baseline, env, loc, false)
	}
	return d.runStagedIntelligence(ctx, report, workspace, baseline, env, loc, true)
}

func (d *Diagnoser) runStagedIntelligence(ctx context.Context, report *Report, workspace string, baseline Baseline, env Environment, loc Localization, persist bool) error {
	repoID := "local:" + d.cfg.RepoPath
	revisionID := "revision:" + env.HeadCommit
	if persist {
		if err := d.cfg.Store.SaveRepository(domain.Repository{ID: repoID, Provider: "local", CanonicalID: d.cfg.RepoPath, Name: d.cfg.RepoPath}); err != nil {
			return err
		}
		if err := d.cfg.Store.SaveRevision(domain.Revision{ID: revisionID, RepositoryID: repoID, CommitSHA: env.HeadCommit, CreatedAt: report.CreatedAt}); err != nil {
			return err
		}
		if err := d.persistReportEvidence(report); err != nil {
			return err
		}
	}

	artifactCache, err := d.openArtifactCache()
	if err != nil {
		report.Uncertainty = append(report.Uncertainty, "artifact cache unavailable: "+err.Error())
	}

	overview, err := d.stageOverview(ctx, report, workspace, repoID, revisionID, env.HeadCommit, artifactCache)
	if err != nil {
		return err
	}
	report.Overview = &overview

	executionID := "execution:" + report.InvestigationID
	if persist {
		if err := d.cfg.Store.SaveCIExecution(domain.CIExecution{ID: executionID, RepositoryID: repoID, HeadRevisionID: revisionID, Provider: "local", ExternalExecutionID: report.InvestigationID, Status: string(report.Classification), StartedAt: &baseline.StartedAt, CompletedAt: &baseline.FinishedAt}); err != nil {
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
	stage.Count("episodes", len(failures))
	stage.Done("completed", nil)

	snapshot, indexMode, err := d.stageIndex(ctx, report, workspace, repoID, revisionID, env.HeadCommit, loc, artifactCache)
	if err != nil {
		return err
	}
	report.IndexingMode = indexMode
	if persist {
		for _, n := range snapshot.Nodes {
			if err := d.cfg.Store.SaveProgramNode(n); err != nil {
				return err
			}
		}
		for _, r := range snapshot.Relationships {
			if err := d.cfg.Store.SaveRelationship(r); err != nil {
				return err
			}
		}
	}

	frames := architectureFrames(baseline, failures)
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

	candStage := d.metrics.Begin(observability.StageCandidateGeneration)
	candidates, relations := localization.Generate(snapshot, localization.Input{InvestigationID: domain.ID(report.InvestigationID), RepositoryID: repoID, RevisionID: revisionID, FailureIDs: failureIDs, EvidenceIDs: evidenceIDs, StackFrames: frames, FailureText: failureText(baseline), ChangedIdentities: changed, MaxDepth: 2, MaxCandidates: 100})
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
		for _, r := range relations {
			if err := d.cfg.Store.SaveRelationship(r); err != nil {
				return err
			}
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

	hypStage := d.metrics.Begin(observability.StageHypothesisGeneration)
	report.Hypotheses = reasoning.Generate(domain.ID(report.InvestigationID), discovery.Groups, candidates)
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
		finding := domain.DiagnosticFinding{ID: "finding:" + report.InvestigationID, InvestigationID: domain.ID(report.InvestigationID), Kind: "candidate_localization", Statement: fmt.Sprintf("Candidate locations were ranked from execution and repository evidence; top candidate is %s", candidates[0].Location.SymbolIdentity), EvidenceIDs: candidates[0].SupportingEvidenceIDs, CandidateIDs: []string{candidates[0].ID}, Status: "potential", Uncertainty: []string{"candidate ranking is not a causal proof"}, CreatedAt: time.Now().UTC()}
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

func (d *Diagnoser) stageIndex(ctx context.Context, report *Report, workspace, repoID, revisionID, commitSHA string, loc Localization, artifactCache *cache.FSCache) (programrepo.Snapshot, string, error) {
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
