package diagnosis

import (
	"testing"

	"github.com/causent/malenia/internal/domain"
)

func TestRepairFromResultDoesNotUpgradeRootCauseOrCausality(t *testing.T) {
	result := domain.DiagnosisResult{
		InvestigationID: "repair-1",
		Reproduction:    &domain.Reproduction{Reproducible: true},
		Patch: &domain.Patch{
			ID:                 "patch-1",
			Status:             domain.PatchValidated,
			ChangedFiles:       []string{"bug.py"},
			Diff:               "diff",
			VerificationStatus: string(domain.VerificationPassed),
		},
	}
	assessment := RepairFromResult(result)
	if assessment.Status != "patch_verified" || assessment.Verification != string(domain.VerificationPassed) {
		t.Fatalf("unexpected repair assessment: %+v", assessment)
	}
	if assessment.InvestigationID != "repair-1" || len(assessment.ChangedFiles) != 1 {
		t.Fatalf("repair provenance was not preserved: %+v", assessment)
	}
}

func TestRepairFromResultPreservesUnavailableVerification(t *testing.T) {
	assessment := RepairFromResult(domain.DiagnosisResult{
		InvestigationID: "repair-2",
		Limitations:     []string{"no patch candidate"},
	})
	if assessment.Status != "completed_without_verified_patch" || assessment.Verification != "" {
		t.Fatalf("repair was overstated: %+v", assessment)
	}
	if len(assessment.Limitations) != 1 {
		t.Fatalf("limitations were not preserved: %+v", assessment)
	}
}
