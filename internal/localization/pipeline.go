package localization

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/causent/malenia/internal/domain"
	programrepo "github.com/causent/malenia/internal/repository"
)

type Frame struct {
	File        string
	Line        int
	EvidenceIDs []domain.ID
	FailureIDs  []string
}

type Input struct {
	InvestigationID       domain.ID
	RepositoryID          string
	RevisionID            string
	FailureIDs            []string
	EvidenceIDs           []domain.ID
	StackFrames           []Frame
	FailureText           string
	ChangedIdentities     map[string]bool
	RuntimeEvidenceIDs    []domain.ID
	HistoricalEvidenceIDs []domain.ID
	MaxDepth              int
	MaxCandidates         int
}

// GenerateObserved creates conservative candidates directly from stack-frame
// observations. These are locations mentioned by execution evidence, not
// indexed symbols and not causal conclusions.
func GenerateObserved(frames []Frame, input Input) ([]domain.CandidateLocation, []domain.Relationship) {
	candidates := map[string]domain.CandidateLocation{}
	var relations []domain.Relationship
	for _, frame := range frames {
		path := cleanPath(frame.File)
		if path == "" {
			continue
		}
		identity := "observed:" + string(input.InvestigationID) + ":" + string(input.RepositoryID) + ":" + string(input.RevisionID) + ":" + path
		if frame.Line > 0 {
			identity += ":" + strconv.Itoa(frame.Line)
		}
		id := "candidate:observed:" + digest(identity)
		candidate, ok := candidates[id]
		if !ok {
			candidate = domain.CandidateLocation{
				ID:              id,
				InvestigationID: input.InvestigationID,
				Location: domain.CodeLocation{
					ID:             "location:" + id,
					RepositoryID:   input.RepositoryID,
					RevisionID:     input.RevisionID,
					FilePath:       path,
					SymbolIdentity: identity,
					StartLine:      frame.Line,
					EndLine:        frame.Line,
					LocationType:   "observed_frame",
				},
				Status: "observed",
			}
			candidate.Score = evaluateSignals(CandidateContext{Execution: true, Evidence: input.EvidenceIDs})
			candidate.Score.ScoringPolicyVersion = PolicyVersion
			candidates[id] = candidate
		}
		candidate.SupportingEvidenceIDs = appendUnique(candidate.SupportingEvidenceIDs, input.EvidenceIDs...)
		candidate.SupportingEvidenceIDs = appendUnique(candidate.SupportingEvidenceIDs, frame.EvidenceIDs...)
		candidates[id] = candidate
		for _, failureID := range frame.FailureIDs {
			relations = append(relations, domain.Relationship{
				ID:              "failure:" + failureID + ":" + id + ":MANIFESTED_AT",
				InvestigationID: input.InvestigationID,
				SourceType:      "failure_episode",
				SourceID:        failureID,
				TargetType:      "candidate_location",
				TargetID:        id,
				Type:            "MANIFESTED_AT",
				RevisionID:      input.RevisionID,
				EvidenceIDs:     appendUnique(append([]domain.ID{}, input.EvidenceIDs...), frame.EvidenceIDs...),
			})
		}
	}
	result := make([]domain.CandidateLocation, 0, len(candidates))
	for _, candidate := range candidates {
		result = append(result, candidate)
	}
	result = Rank(result, DefaultWeights)
	if input.MaxCandidates > 0 && len(result) > input.MaxCandidates {
		result = result[:input.MaxCandidates]
	}
	return result, uniqueRelationships(relations)
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:8])
}

// Generate creates candidates from execution evidence and then expands them
// through the program graph. It does not make a causal claim.
func Generate(snapshot programrepo.Snapshot, input Input) ([]domain.CandidateLocation, []domain.Relationship) {
	if input.MaxDepth <= 0 {
		input.MaxDepth = 2
	}
	if input.MaxCandidates <= 0 {
		input.MaxCandidates = 100
	}
	nodes := map[string]domain.ProgramNode{}
	byPath := map[string][]domain.ProgramNode{}
	for _, n := range snapshot.Nodes {
		nodes[n.ID] = n
		if n.FilePath != "" {
			byPath[n.FilePath] = append(byPath[n.FilePath], n)
		}
	}
	edges := map[string][]domain.Relationship{}
	for _, e := range snapshot.Relationships {
		edges[e.SourceID] = append(edges[e.SourceID], e)
	}
	candidates := map[string]*domain.CandidateLocation{}
	relations := []domain.Relationship{}
	add := func(n domain.ProgramNode, score domain.ScoreVector, evidence []domain.ID, relationType string, failureIDs []string) {
		if n.Type == "File" || n.Type == "Dependency" {
			return
		}
		c := candidates[n.ID]
		if c == nil {
			c = &domain.CandidateLocation{ID: "candidate:" + n.ID, InvestigationID: input.InvestigationID, Location: domain.CodeLocation{ID: "location:" + n.ID, RepositoryID: n.RepositoryID, RevisionID: n.RevisionID, FilePath: n.FilePath, SymbolIdentity: n.Identity, StartLine: n.StartLine, EndLine: n.EndLine, LocationType: n.Type}, Status: "open"}
			candidates[n.ID] = c
		}
		mergeScore(&c.Score, score)
		c.SupportingEvidenceIDs = appendUnique(c.SupportingEvidenceIDs, evidence...)
		for _, failureID := range failureIDs {
			relations = append(relations, domain.Relationship{ID: "failure:" + failureID + ":" + c.ID + ":" + relationType, InvestigationID: input.InvestigationID, SourceType: "failure_episode", SourceID: failureID, TargetType: "candidate_location", TargetID: c.ID, Type: relationType, RevisionID: n.RevisionID, EvidenceIDs: evidence})
		}
	}
	for _, frame := range input.StackFrames {
		framePath := cleanPath(frame.File)
		matched := byPath[framePath]
		if len(matched) == 0 {
			for path, nodes := range byPath {
				if strings.HasSuffix(path, "/"+framePath) || strings.HasSuffix(framePath, "/"+path) {
					matched = append(matched, nodes...)
				}
			}
		}
		for _, n := range matched {
			if frame.Line > 0 && (frame.Line < n.StartLine || frame.Line > n.EndLine) {
				continue
			}
			ev := append(append([]domain.ID{}, input.EvidenceIDs...), frame.EvidenceIDs...)
			add(n, evaluateSignals(CandidateContext{Execution: true, Evidence: ev}), ev, "MANIFESTED_AT", frame.FailureIDs)
		}
	}
	for _, n := range snapshot.Nodes {
		if n.Type == "Test" && (strings.Contains(input.FailureText, n.Name) || strings.Contains(input.FailureText, n.FilePath)) {
			ev := input.EvidenceIDs
			add(n, evaluateSignals(CandidateContext{Execution: true, Behavioural: true, Evidence: ev}), ev, "ASSOCIATED_WITH", input.FailureIDs)
		}
	}
	for _, n := range snapshot.Nodes {
		if input.ChangedIdentities[n.Identity] || n.Changed {
			ev := input.EvidenceIDs
			add(n, evaluateSignals(CandidateContext{Changed: true, Evidence: ev}), ev, "ASSOCIATED_WITH", input.FailureIDs)
		}
	}
	// Expand every discovered symbol through typed program relationships. This
	// includes unchanged callers, callees, and test dependencies.
	for depth := 0; depth < input.MaxDepth; depth++ {
		current := make([]string, 0, len(candidates))
		for id := range candidates {
			current = append(current, id)
		}
		for _, id := range current {
			for _, e := range edges[id] {
				target, ok := nodes[e.TargetID]
				if !ok {
					continue
				}
				ev := append([]domain.ID{}, input.EvidenceIDs...)
				score := evaluateSignals(CandidateContext{Expanded: true, Evidence: ev})
				if e.Type == "TESTS" {
					score = evaluateSignals(CandidateContext{Expanded: true, Behavioural: true, Evidence: ev})
				}
				add(target, score, ev, "RELATED_TO", input.FailureIDs)
			}
		}
	}
	result := make([]domain.CandidateLocation, 0, len(candidates))
	for _, c := range candidates {
		c.Score.ScoringPolicyVersion = PolicyVersion
		result = append(result, *c)
	}
	ranked := Rank(result, DefaultWeights)
	if len(ranked) > input.MaxCandidates {
		ranked = ranked[:input.MaxCandidates]
	}
	return ranked, uniqueRelationships(relations)
}

func cleanPath(p string) string {
	return filepath.ToSlash(filepath.Clean(strings.TrimPrefix(filepath.ToSlash(p), "./")))
}
func vector(dim string, value float64, evidence []domain.ID) domain.ScoreVector {
	v := domain.ScoreVector{EvidenceByDimension: map[string][]domain.ID{dim: evidence}, ScoringPolicyVersion: PolicyVersion}
	switch dim {
	case "execution":
		v.ExecutionRelevance = value
	case "change":
		v.ChangeRelevance = value
	case "dependency":
		v.DependencyRelevance = value
	case "behavioural":
		v.BehaviouralRelevance = value
	case "historical":
		v.HistoricalRelevance = value
	case "runtime":
		v.RuntimeRelevance = value
	}
	v.AvailableDimensions = []string{dim}
	return v
}
func mergeScore(dst *domain.ScoreVector, src domain.ScoreVector) {
	for _, d := range src.AvailableDimensions {
		if !contains(dst.AvailableDimensions, d) {
			dst.AvailableDimensions = append(dst.AvailableDimensions, d)
		}
		switch d {
		case "execution":
			if src.ExecutionRelevance > dst.ExecutionRelevance {
				dst.ExecutionRelevance = src.ExecutionRelevance
			}
		case "change":
			if src.ChangeRelevance > dst.ChangeRelevance {
				dst.ChangeRelevance = src.ChangeRelevance
			}
		case "dependency":
			if src.DependencyRelevance > dst.DependencyRelevance {
				dst.DependencyRelevance = src.DependencyRelevance
			}
		case "behavioural":
			if src.BehaviouralRelevance > dst.BehaviouralRelevance {
				dst.BehaviouralRelevance = src.BehaviouralRelevance
			}
		case "historical":
			if src.HistoricalRelevance > dst.HistoricalRelevance {
				dst.HistoricalRelevance = src.HistoricalRelevance
			}
		case "runtime":
			if src.RuntimeRelevance > dst.RuntimeRelevance {
				dst.RuntimeRelevance = src.RuntimeRelevance
			}
		}
		if dst.EvidenceByDimension == nil {
			dst.EvidenceByDimension = map[string][]domain.ID{}
		}
		dst.EvidenceByDimension[d] = appendUnique(dst.EvidenceByDimension[d], src.EvidenceByDimension[d]...)
	}
}
func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
func appendUnique(xs []domain.ID, ys ...domain.ID) []domain.ID {
	seen := map[domain.ID]bool{}
	for _, x := range xs {
		seen[x] = true
	}
	for _, y := range ys {
		if y != "" && !seen[y] {
			xs = append(xs, y)
			seen[y] = true
		}
	}
	return xs
}
func uniqueRelationships(in []domain.Relationship) []domain.Relationship {
	seen := map[string]bool{}
	out := in[:0]
	for _, r := range in {
		if !seen[r.ID] {
			seen[r.ID] = true
			out = append(out, r)
		}
	}
	return out
}
