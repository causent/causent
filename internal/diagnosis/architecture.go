package diagnosis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/causent/causent/internal/domain"
	"github.com/causent/causent/internal/history"
	"github.com/causent/causent/internal/investigation"
	"github.com/causent/causent/internal/localization"
	"github.com/causent/causent/internal/reasoning"
	"github.com/causent/causent/internal/relationships"
	programrepo "github.com/causent/causent/internal/repository"
)

var (
	pythonFrame        = regexp.MustCompile(`File "([^"]+)", line ([0-9]+)`)
	goFrame            = regexp.MustCompile(`([^\s()]+\.go):([0-9]+)`)
	failureLine        = regexp.MustCompile(`(?m)^--- FAIL: ([^ (]+)`)
	genericFailureLine = regexp.MustCompile(`(?m)^FAIL\s+([^ (]+)`)
	pytestFailure      = regexp.MustCompile(`(?m)^FAILED\s+([^\s]+)(?:\s+-\s*(.*))?$`)
	jestFailure        = regexp.MustCompile(`(?m)^\s*[●•]\s+(.+)$`)
)

type failureObservation struct {
	Test    string
	Message string
}

// parseFailureObservations extracts multiple test failures from one CI log.
// It is intentionally parser-shaped rather than a root-cause classifier.
func parseFailureObservations(text string) []failureObservation {
	seen := map[string]bool{}
	var out []failureObservation
	add := func(test, message string) {
		test, message = strings.TrimSpace(test), strings.TrimSpace(message)
		if test == "" {
			return
		}
		if message == "" {
			message = test
		}
		key := test + "\x00" + message
		if !seen[key] {
			seen[key] = true
			out = append(out, failureObservation{Test: test, Message: message})
		}
	}
	for _, match := range failureLine.FindAllStringSubmatch(text, -1) {
		add(match[1], match[1])
	}
	for _, match := range genericFailureLine.FindAllStringSubmatch(text, -1) {
		add(match[1], match[1])
	}
	for _, match := range pytestFailure.FindAllStringSubmatch(text, -1) {
		add(match[1], match[2])
	}
	for _, match := range jestFailure.FindAllStringSubmatch(text, -1) {
		add(match[1], match[1])
	}
	if strings.Contains(text, "<testsuite") || strings.Contains(text, "<testsuites") {
		if junit, err := parseJUnitFailures(text); err == nil {
			for _, observation := range junit {
				add(observation.Test, observation.Message)
			}
		}
	}
	return out
}

func (d *Diagnoser) persistArchitecture(ctx context.Context, report *Report, workspace string, baseline Baseline, env Environment, loc Localization) error {
	if d.cfg.Store == nil {
		return nil
	}
	repoID := "local:" + d.cfg.RepoPath
	revisionID := "revision:" + env.HeadCommit
	if err := d.cfg.Store.SaveRepository(domain.Repository{ID: repoID, Provider: "local", CanonicalID: d.cfg.RepoPath, Name: d.cfg.RepoPath}); err != nil {
		return err
	}
	if err := d.cfg.Store.SaveRevision(domain.Revision{ID: revisionID, RepositoryID: repoID, CommitSHA: env.HeadCommit, CreatedAt: report.CreatedAt}); err != nil {
		return err
	}
	if err := d.persistReportEvidence(report); err != nil {
		return err
	}
	executionID := "execution:" + report.InvestigationID
	if err := d.cfg.Store.SaveCIExecution(domain.CIExecution{ID: executionID, RepositoryID: repoID, HeadRevisionID: revisionID, Provider: "local", ExternalExecutionID: report.InvestigationID, Status: string(report.Classification), StartedAt: &baseline.StartedAt, CompletedAt: &baseline.FinishedAt}); err != nil {
		return err
	}
	failures, err := d.persistFailureEpisodes(report, executionID, baseline)
	if err != nil {
		return err
	}
	report.FailureEpisodes = failures
	snapshot, err := (programrepo.Analyzer{}).Analyze(ctx, workspace, repoID, revisionID, env.HeadCommit)
	if err != nil {
		return err
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
	frames := architectureFrames(baseline, failures)
	var evidenceIDs []domain.ID
	for _, e := range report.Evidence {
		evidenceIDs = append(evidenceIDs, domain.ID(e.ID))
	}
	failureIDs := make([]string, 0, len(failures))
	for _, failure := range failures {
		failureIDs = append(failureIDs, failure.ID)
	}
	candidates, relations := localization.Generate(snapshot, localization.Input{InvestigationID: domain.ID(report.InvestigationID), RepositoryID: repoID, RevisionID: revisionID, FailureIDs: failureIDs, EvidenceIDs: evidenceIDs, StackFrames: frames, FailureText: failureText(baseline), ChangedIdentities: changed, MaxDepth: 2, MaxCandidates: 100})
	report.Candidates = candidates
	report.Relationships = relations
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
	discovery := relationships.Discover(domain.ID(report.InvestigationID), failures, candidates, relations)
	report.FailureGroups = discovery.Groups
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
	// Historical context is retrieved only after the current revision has been
	// localized. This keeps old conclusions subordinate to current evidence.
	historical, err := history.Discover(d.cfg.Store, history.Input{InvestigationID: domain.ID(report.InvestigationID), RepositoryID: repoID, RevisionID: revisionID, Failures: failures, Candidates: candidates, EvidenceIDs: evidenceIDs})
	if err != nil {
		return err
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
	for _, stage := range []string{"AnalyzeRepository", "GenerateCandidates", "DiscoverRelationships"} {
		activity := investigation.NewActivity(domain.ID(report.InvestigationID), "activity:"+report.InvestigationID+":"+stage, stage, nil, evidenceIDsToStrings(evidenceIDs))
		activity = investigation.Complete(activity, []string{"report:" + report.InvestigationID + ":" + stage})
		if err := d.cfg.Store.SaveActivity(activity); err != nil {
			return err
		}
	}
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
		if err := d.cfg.Store.SaveHypothesis(assessed); err != nil {
			return err
		}
		if err := d.cfg.Store.SaveHypothesisHistory(domain.HypothesisHistory{ID: domain.NewID(), HypothesisID: assessed.ID, InvestigationID: assessed.InvestigationID, PreviousStatus: domain.HypProposed, NextStatus: assessed.Status, Evaluation: "assessment from persisted evidence", CreatedAt: time.Now().UTC()}); err != nil {
			return err
		}
	}
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
		if err := d.cfg.Store.SaveFinding(finding); err != nil {
			return err
		}
		if err := d.cfg.Store.SaveClaimValidation(domain.ClaimValidation{ClaimID: finding.ID, Valid: validation.Valid, Reasons: validation.Reasons, ValidatedAt: validation.ValidatedAt}); err != nil {
			return err
		}
	}
	if len(candidates) > 0 {
		finding := domain.DiagnosticFinding{ID: "finding:" + report.InvestigationID, InvestigationID: domain.ID(report.InvestigationID), Kind: "candidate_localization", Statement: fmt.Sprintf("Candidate locations were ranked from execution and repository evidence; top candidate is %s", candidates[0].Location.SymbolIdentity), EvidenceIDs: candidates[0].SupportingEvidenceIDs, CandidateIDs: []string{candidates[0].ID}, Status: "potential", Uncertainty: []string{"candidate ranking is not a causal proof"}, CreatedAt: time.Now().UTC()}
		if err := d.cfg.Store.SaveFinding(finding); err != nil {
			return err
		}
	}
	return nil
}

func (d *Diagnoser) persistReportEvidence(report *Report) error {
	for _, item := range report.Evidence {
		if err := d.cfg.Store.SaveEvidence(domain.Evidence{ID: domain.ID(item.ID), InvestigationID: domain.ID(report.InvestigationID), Type: domain.EvidenceType(item.Kind), Source: item.Source, Timestamp: report.CreatedAt, ContentRef: item.Kind, Digest: item.Digest, Payload: item.Detail, Provenance: "diagnosis report evidence"}); err != nil {
			return err
		}
	}
	return nil
}

func (d *Diagnoser) persistFailureEpisodes(report *Report, executionID string, baseline Baseline) ([]domain.FailureEpisode, error) {
	seen := map[string]bool{}
	var episodes []domain.FailureEpisode
	for _, attempt := range baseline.Results {
		if !attempt.Failed() {
			continue
		}
		observations := parseFailureObservations(attempt.Stderr)
		if len(observations) == 0 {
			observations = []failureObservation{{Message: failureSignature(attempt.Stderr)}}
		}
		for _, observation := range observations {
			sig := observation.Message
			if sig == "" {
				sig = "exit_code:" + fmt.Sprint(attempt.ExitCode)
			}
			if seen[sig] {
				continue
			}
			seen[sig] = true
			sum := sha256.Sum256([]byte(report.InvestigationID + sig))
			id := "failure:" + hex.EncodeToString(sum[:8])
			episode := domain.FailureEpisode{ID: id, ExecutionID: executionID, TestIdentifier: observation.Test, FailureMessage: sig, FailureType: string(report.Classification), Status: "observed"}
			episodes = append(episodes, episode)
			if err := d.cfg.Store.SaveFailureEpisode(episode); err != nil {
				return nil, err
			}
		}
	}
	// CI logs often contain failures from several jobs/tests but are not part
	// of reproduction attempts. Treat them as observations, never as reruns.
	for _, item := range report.Evidence {
		if item.Kind != "original_ci_log" {
			continue
		}
		for _, observation := range parseFailureObservations(item.Detail) {
			if seen[observation.Message] {
				continue
			}
			seen[observation.Message] = true
			sum := sha256.Sum256([]byte(report.InvestigationID + observation.Message))
			episode := domain.FailureEpisode{ID: "failure:" + hex.EncodeToString(sum[:8]), ExecutionID: executionID, TestIdentifier: observation.Test, FailureMessage: observation.Message, FailureType: string(report.Classification), Status: "observed_from_ci_artifact"}
			episodes = append(episodes, episode)
			if err := d.cfg.Store.SaveFailureEpisode(episode); err != nil {
				return nil, err
			}
		}
	}
	return episodes, nil
}

func evidenceIDsToStrings(ids []domain.ID) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, string(id))
	}
	return out
}

func evidenceIDsOfHistorical(values []domain.Evidence) []domain.ID {
	out := make([]domain.ID, 0, len(values))
	for _, value := range values {
		out = append(out, value.ID)
	}
	return out
}
func failureSignature(text string) string {
	if m := failureLine.FindStringSubmatch(text); len(m) > 1 {
		return m[1]
	}
	if m := genericFailureLine.FindStringSubmatch(text); len(m) > 1 {
		return m[1]
	}
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if len(lines) > 0 {
		return lines[len(lines)-1]
	}
	return ""
}
func failureText(b Baseline) string {
	var bld strings.Builder
	for _, a := range b.Results {
		bld.WriteString(a.Stderr)
		bld.WriteByte('\n')
	}
	return bld.String()
}
func architectureFrames(b Baseline, failures []domain.FailureEpisode) []localization.Frame {
	var out []localization.Frame
	for _, a := range b.Results {
		text := a.Stderr
		failureIDs := failureIDsForText(a.Stderr, failures)
		for _, m := range pythonFrame.FindAllStringSubmatch(text, -1) {
			out = append(out, localization.Frame{File: m[1], Line: atoi(m[2]), FailureIDs: failureIDs})
		}
		for _, m := range goFrame.FindAllStringSubmatch(text, -1) {
			out = append(out, localization.Frame{File: m[1], Line: atoi(m[2]), FailureIDs: failureIDs})
		}
	}
	return out
}

func failureIDsForText(text string, failures []domain.FailureEpisode) []string {
	var out []string
	for _, failure := range failures {
		if strings.Contains(text, failure.FailureMessage) || strings.Contains(text, failure.TestIdentifier) {
			out = append(out, failure.ID)
		}
	}
	return out
}
func atoi(v string) int {
	var n int
	for _, r := range v {
		if r >= '0' && r <= '9' {
			n = n*10 + int(r-'0')
		}
	}
	return n
}
