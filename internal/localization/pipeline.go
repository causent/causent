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
	File        string      `json:"file"`
	Line        int         `json:"line"`
	Function    string      `json:"function,omitempty"`
	LogLine     int         `json:"log_line,omitempty"`
	EvidenceIDs []domain.ID `json:"evidence_ids,omitempty"`
	FailureIDs  []string    `json:"failure_ids,omitempty"`
	Provenance  string      `json:"provenance,omitempty"`
}

type Input struct {
	InvestigationID        domain.ID
	RepositoryID           string
	RevisionID             string
	FailureIDs             []string
	EvidenceIDs            []domain.ID
	StackFrames            []Frame
	FailureText            string
	ChangedIdentities      map[string]bool
	RuntimeEvidenceIDs     []domain.ID
	HistoricalEvidenceIDs  []domain.ID
	ChangeEvidenceIDs      []domain.ID
	DependencyEvidenceIDs  []domain.ID
	BehaviouralEvidenceIDs []domain.ID
	MaxDepth               int
	MaxCandidates          int
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
					Provenance:     "direct_stack_frame",
				},
				Status: "observed",
			}
			candidate.Score = evaluateSignals(CandidateContext{Execution: len(frame.EvidenceIDs) > 0, Evidence: frame.EvidenceIDs})
			candidate.Score.ScoringPolicyVersion = PolicyVersion
			candidates[id] = candidate
		}
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
				Metadata:        map[string]string{"provenance": "direct_stack_frame"},
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
	const maxRelationships = 600
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
			if len(relations) >= maxRelationships {
				break
			}
			provenance := c.Location.Provenance
			if provenance == "" {
				provenance = relationType
			}
			relations = append(relations, domain.Relationship{ID: "failure:" + failureID + ":" + c.ID + ":" + relationType, InvestigationID: input.InvestigationID, SourceType: "failure_episode", SourceID: failureID, TargetType: "candidate_location", TargetID: c.ID, Type: relationType, RevisionID: n.RevisionID, EvidenceIDs: evidence, Metadata: map[string]string{"provenance": provenance}})
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
		// A frame is direct evidence for one most-specific enclosing symbol.
		// Broader containers must not inherit the same execution claim.
		var best *domain.ProgramNode
		for i := range matched {
			n := &matched[i]
			if frame.Line <= 0 || frame.Line < n.StartLine || frame.Line > n.EndLine {
				continue
			}
			if best == nil || (n.EndLine-n.StartLine) < (best.EndLine-best.StartLine) {
				best = n
			}
		}
		if best != nil {
			n := *best
			ev := append([]domain.ID{}, frame.EvidenceIDs...)
			scoreEvidence := frame.EvidenceIDs
			if len(scoreEvidence) == 0 {
				scoreEvidence = nil
			}
			score := domain.ScoreVector{ExecutionRelevance: 1, AvailableDimensions: []string{"execution"}, EvidenceByDimension: map[string][]domain.ID{"execution": scoreEvidence}, ScoringPolicyVersion: PolicyVersion}
			add(n, score, ev, "MANIFESTED_AT", frame.FailureIDs)
			c := candidates[n.ID]
			c.Location.Provenance = "enclosing_symbol"
			candidates[n.ID] = c
		}
	}
	for _, n := range snapshot.Nodes {
		if n.Type == "Test" && (strings.Contains(input.FailureText, n.Name) || strings.Contains(input.FailureText, n.FilePath)) {
			ev := input.BehaviouralEvidenceIDs
			add(n, evaluateSignals(CandidateContext{Behavioural: true, Evidence: ev, BehaviouralEvidence: ev}), ev, "ASSOCIATED_WITH", input.FailureIDs)
		}
	}
	for _, n := range snapshot.Nodes {
		if input.ChangedIdentities[n.Identity] || n.Changed {
			// A changed symbol is useful supporting evidence, but a diff alone
			// does not make it a failure candidate. Only promote it when it is
			// already connected to execution/test evidence; otherwise unrelated
			// changed files can outrank the actual failing stack frames.
			if _, exists := candidates[n.ID]; !exists {
				continue
			}
			ev := input.ChangeEvidenceIDs
			add(n, evaluateSignals(CandidateContext{Changed: true, Evidence: ev, ChangeEvidence: ev}), ev, "ASSOCIATED_WITH", input.FailureIDs)
			if candidates[n.ID].Location.Provenance == "" {
				candidates[n.ID].Location.Provenance = "changed_file"
			}
		}
	}
	// Expand only AST-verified calls. Heuristic references and package-level
	// relationships remain available in the graph but do not create candidates.
	for depth := 0; depth < input.MaxDepth; depth++ {
		current := make([]string, 0, len(candidates))
		for id := range candidates {
			current = append(current, id)
		}
		for _, id := range current {
			for _, e := range edges[id] {
				if e.Type != "CALLS" || e.Metadata["provenance"] != "verified_static_call" {
					continue
				}
				target, ok := nodes[e.TargetID]
				if !ok {
					continue
				}
				ev := append([]domain.ID{}, e.EvidenceIDs...)
				score := domain.ScoreVector{ScoringPolicyVersion: PolicyVersion}
				add(target, score, ev, "RELATED_TO", input.FailureIDs)
				if c := candidates[target.ID]; c != nil && c.Location.Provenance == "" {
					c.Location.Provenance = "inferred_caller"
				}
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
