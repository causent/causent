package diagnosis

import "testing"

func strictUnknown(reqs ...EvidenceRequirement) InvestigationUnknown {
	return InvestigationUnknown{ID: "shutdown-ordering", Requirements: reqs, Status: "unresolved"}
}

func TestStrictObjectiveRejectsUnrelatedRelationshipEvidence(t *testing.T) {
	u := strictUnknown(EvidenceRequirement{ClaimKind: "synchronization-ordering", Subject: "pkg.Cacher.stopWg", MinimumBasis: "SourceVerified", Ordering: "happens-before"})
	got := evaluateStrictObjective(u, []EvidenceItem{{ID: "rel", Kind: "source_code", ClaimKind: "source_code", Basis: "SourceVerified", DeclarationID: "watch_cache_test.go:immediateTicker.Stop"}}, "head")
	if got.Resolved || len(got.Missing) != 1 {
		t.Fatalf("unrelated evidence resolved objective: %+v", got)
	}
}

func TestStrictObjectiveRejectsInferredAndWrongSubjectEvidence(t *testing.T) {
	req := EvidenceRequirement{ClaimKind: "synchronization-ordering", Subject: "pkg.Cacher.stopWg", MinimumBasis: "SourceVerified", Ordering: "happens-before"}
	for _, ev := range []EvidenceItem{
		{ID: "inferred", ClaimKind: req.ClaimKind, Basis: "Inferred", DeclarationID: req.Subject, Ordering: req.Ordering},
		{ID: "wrong-subject", ClaimKind: req.ClaimKind, Basis: "SourceVerified", DeclarationID: "other.Cacher.stopWg", Ordering: req.Ordering},
	} {
		if result := evaluateStrictObjective(strictUnknown(req), []EvidenceItem{ev}, "head"); result.Resolved {
			t.Fatalf("invalid evidence resolved objective: %+v", result)
		}
	}
}

func TestStrictObjectiveRequiresRuntimeInstanceIdentity(t *testing.T) {
	req := EvidenceRequirement{ClaimKind: "same-runtime-instance", MinimumBasis: "RuntimeObserved", SameInstance: true}
	result := evaluateStrictObjective(strictUnknown(req), []EvidenceItem{{ID: "decl", ClaimKind: req.ClaimKind, Basis: "SourceVerified", DeclarationID: "pkg.Cacher.stopWg"}}, "head")
	if result.Resolved {
		t.Fatal("declaration identity satisfied runtime instance requirement")
	}
	result = evaluateStrictObjective(strictUnknown(req), []EvidenceItem{{ID: "instance", ClaimKind: req.ClaimKind, Basis: "RuntimeObserved", InstanceID: "instance-1"}}, "head")
	if !result.Resolved {
		t.Fatalf("runtime instance evidence did not satisfy requirement: %+v", result)
	}
}

func TestRaceObservationCannotSatisfySynchronizationRequirement(t *testing.T) {
	req := EvidenceRequirement{ClaimKind: "synchronization-ordering", MinimumBasis: "SourceVerified", Ordering: "happens-before"}
	result := evaluateStrictObjective(strictUnknown(req), []EvidenceItem{{ID: "race", ClaimKind: "RuntimeObservedRace", Basis: "RuntimeObserved", RunID: "run-1"}}, "head")
	if result.Resolved {
		t.Fatal("race observation substituted for ordering proof")
	}
}

func TestContradictoryEvidenceDoesNotResolvePositiveObjective(t *testing.T) {
	req := EvidenceRequirement{ClaimKind: "synchronization-ordering", MinimumBasis: "SourceVerified", Ordering: "happens-before"}
	result := evaluateStrictObjective(strictUnknown(req), []EvidenceItem{{ID: "contradiction", ClaimKind: "synchronization-absent", Basis: "SourceVerified"}}, "head")
	if result.Resolved || len(result.Missing) == 0 {
		t.Fatalf("contradictory evidence resolved positive objective: %+v", result)
	}
}

func TestLegacyEvidenceDoesNotSatisfyStrictObjective(t *testing.T) {
	u := strictUnknown(EvidenceRequirement{ClaimKind: "synchronization-ordering", MinimumBasis: "SourceVerified"})
	result := evaluateStrictObjective(u, []EvidenceItem{{ID: "legacy", Kind: "source synchronization", Detail: "WaitGroup Add and Wait"}}, "head")
	if result.Resolved {
		t.Fatal("legacy evidence satisfied new strict requirement")
	}
}
