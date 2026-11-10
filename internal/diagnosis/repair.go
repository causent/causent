package diagnosis

import "github.com/causent/malenia/internal/domain"

// RepairFromResult converts the explicit repair engine result into the
// diagnosis report contract. It keeps patch verification data available to
// callers without upgrading an experimentally verified patch into a root-cause
// or PR-causality claim.
func RepairFromResult(result domain.DiagnosisResult) *RepairAssessment {
	assessment := &RepairAssessment{
		Status:          "completed_without_verified_patch",
		InvestigationID: string(result.InvestigationID),
		Limitations:     append([]string(nil), result.Limitations...),
	}
	if result.Reproduction != nil {
		assessment.Reproduced = result.Reproduction.Reproducible
	}
	if result.Patch == nil {
		return assessment
	}

	patch := result.Patch
	assessment.Status = "patch_generated"
	assessment.PatchID = string(patch.ID)
	assessment.PatchStatus = string(patch.Status)
	assessment.ChangedFiles = append([]string(nil), patch.ChangedFiles...)
	assessment.Diff = patch.Diff
	assessment.Explanation = patch.Explanation
	assessment.Verification = patch.VerificationStatus
	assessment.VerificationText = patch.VerificationReport
	if patch.VerificationStatus == string(domain.VerificationPassed) {
		assessment.Status = "patch_verified"
	} else {
		assessment.Limitations = append(assessment.Limitations, "patch verification did not pass")
	}
	if patch.Error != "" {
		assessment.Limitations = append(assessment.Limitations, patch.Error)
	}
	return assessment
}
