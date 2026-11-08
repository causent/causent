// Package relationships discovers evidence-backed relationships between
// failures and candidates. It keeps structural relevance separate from causal
// claims.
package relationships

import (
	"github.com/causent/malenia/internal/domain"
	"sort"
	"strings"
)

type Result struct {
	Groups        []domain.FailureGroup
	Relationships []domain.Relationship
}

func Discover(investigationID domain.ID, failures []domain.FailureEpisode, candidates []domain.CandidateLocation, existing []domain.Relationship) Result {
	candidateByFailure := map[string][]string{}
	evidenceByPair := map[string][]domain.ID{}
	for _, r := range existing {
		if r.SourceType == "failure_episode" && r.TargetType == "candidate_location" {
			candidateByFailure[r.SourceID] = append(candidateByFailure[r.SourceID], r.TargetID)
			evidenceByPair[r.SourceID+"\x00"+r.TargetID] = appendUnique(evidenceByPair[r.SourceID+"\x00"+r.TargetID], r.EvidenceIDs...)
		}
	}
	candidatesByID := map[string]domain.CandidateLocation{}
	for _, c := range candidates {
		candidatesByID[c.ID] = c
	}
	groups := []domain.FailureGroup{}
	seen := map[string]bool{}
	for _, failure := range failures {
		if seen[failure.ID] {
			continue
		}
		members := []string{failure.ID}
		shared := map[string]bool{}
		for _, c := range candidateByFailure[failure.ID] {
			shared[c] = true
		}
		for _, other := range failures {
			if other.ID == failure.ID || seen[other.ID] {
				continue
			}
			for _, c := range candidateByFailure[other.ID] {
				if shared[c] {
					members = append(members, other.ID)
					seen[other.ID] = true
					break
				}
			}
		}
		seen[failure.ID] = true
		sort.Strings(members)
		status := "independent"
		if len(members) > 1 {
			status = "potentially_related"
		}
		evidence := []domain.ID{}
		for _, member := range members {
			for _, cid := range candidateByFailure[member] {
				if c, ok := candidatesByID[cid]; ok {
					evidence = appendUnique(evidence, c.SupportingEvidenceIDs...)
					evidence = appendUnique(evidence, evidenceByPair[member+"\x00"+cid]...)
				}
			}
		}
		candidateIDs := []string{}
		for _, member := range members {
			candidateIDs = appendUniqueStrings(candidateIDs, candidateByFailure[member]...)
		}
		groups = append(groups, domain.FailureGroup{ID: groupID(investigationID, members), InvestigationID: investigationID, FailureIDs: members, CandidateIDs: candidateIDs, Status: status, EvidenceIDs: evidence, Version: 1})
	}
	result := Result{Groups: groups}
	for _, group := range groups {
		for i := 0; i < len(group.FailureIDs); i++ {
			for j := i + 1; j < len(group.FailureIDs); j++ {
				typ := "INDEPENDENT_OF"
				if group.Status == "potentially_related" {
					typ = "POTENTIALLY_RELATED"
				}
				result.Relationships = append(result.Relationships, domain.Relationship{ID: "failure-group:" + group.ID + ":" + group.FailureIDs[i] + ":" + group.FailureIDs[j], InvestigationID: investigationID, SourceType: "failure_episode", SourceID: group.FailureIDs[i], TargetType: "failure_episode", TargetID: group.FailureIDs[j], Type: typ, EvidenceIDs: group.EvidenceIDs, Metadata: map[string]string{"causal_claim": "false"}})
			}
		}
	}
	return result
}

func groupID(inv domain.ID, ids []string) string {
	return "failure-group:" + string(inv) + ":" + strings.Join(ids, ",")
}
func appendUnique(dst []domain.ID, values ...domain.ID) []domain.ID {
	seen := map[domain.ID]bool{}
	for _, v := range dst {
		seen[v] = true
	}
	for _, v := range values {
		if v != "" && !seen[v] {
			dst = append(dst, v)
			seen[v] = true
		}
	}
	return dst
}

func appendUniqueStrings(dst []string, values ...string) []string {
	seen := map[string]bool{}
	for _, v := range dst {
		seen[v] = true
	}
	for _, v := range values {
		if v != "" && !seen[v] {
			dst = append(dst, v)
			seen[v] = true
		}
	}
	return dst
}
