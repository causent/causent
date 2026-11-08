package engine

import (
	"context"
	"fmt"
	"strings"

	"github.com/causent/malenia/internal/domain"
)

// ProposalProvider is the optional, separate model call used only to propose
// a patch. It never receives a repository checkout and cannot execute code.
type ProposalProvider interface {
	Propose(context.Context, ProposalInput) (ProposalOutput, error)
}

// ProposalInput is a compact, already validated diagnosis view. Callers must
// populate it from persisted evidence; the provider is not given repository
// access or host configuration.
type ProposalInput struct {
	Command       []string
	Diagnosis     string
	FocusedPath   string
	FocusedLine   int
	UseCase       string
	Evidence      []domain.Evidence
	PriorFeedback string
}

type ProposalOutput struct {
	Patch        string   `json:"patch"`
	ChangedPaths []string `json:"changed_paths"`
	Rationale    string   `json:"rationale"`
	Claims       []Claim  `json:"claims"`
	Confidence   float64  `json:"confidence"`
	Limitations  []string `json:"limitations"`
}

type Claim struct {
	Text        string   `json:"text"`
	EvidenceIDs []string `json:"evidence_ids"`
}

// ValidateProposal checks reference and shape integrity only. Valid evidence
// IDs establish referential integrity, not semantic support for a claim.
func ValidateProposal(input ProposalInput, output ProposalOutput) error {
	if strings.TrimSpace(output.Patch) == "" {
		return fmt.Errorf("proposal patch is empty")
	}
	if output.Confidence < 0 || output.Confidence > 1 {
		return fmt.Errorf("proposal confidence %.3f is outside [0,1]", output.Confidence)
	}
	known := make(map[string]bool, len(input.Evidence))
	for _, evidence := range input.Evidence {
		known[string(evidence.ID)] = true
	}
	validClaims := 0
	for _, claim := range output.Claims {
		if strings.TrimSpace(claim.Text) == "" {
			return fmt.Errorf("proposal claim is empty")
		}
		if len(claim.EvidenceIDs) == 0 {
			continue
		}
		for _, id := range claim.EvidenceIDs {
			if !known[id] {
				return fmt.Errorf("proposal claim references unknown evidence %q", id)
			}
		}
		validClaims++
	}
	if validClaims == 0 {
		return fmt.Errorf("proposal has no claims with valid evidence references")
	}
	return nil
}

// FakeProvider is intentionally small and deterministic for tests.
type FakeProvider struct {
	Output ProposalOutput
}

func (p FakeProvider) Propose(context.Context, ProposalInput) (ProposalOutput, error) {
	return p.Output, nil
}

var proposalSchema = map[string]any{
	"type":                 "object",
	"additionalProperties": false,
	"properties": map[string]any{
		"patch":         map[string]any{"type": "string"},
		"changed_paths": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"rationale":     map[string]any{"type": "string"},
		"claims": map[string]any{"type": "array", "items": map[string]any{"type": "object", "additionalProperties": false,
			"properties": map[string]any{"text": map[string]any{"type": "string"}, "evidence_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}},
			"required":   []string{"text", "evidence_ids"}}},
		"confidence":  map[string]any{"type": "number"},
		"limitations": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
	},
	"required": []string{"patch", "changed_paths", "rationale", "claims", "confidence", "limitations"},
}
