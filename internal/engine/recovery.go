package engine

import (
	"context"
	"log/slog"
	"time"

	"github.com/causent/causent/internal/domain"
)

// RecoveryReport describes what was found and repaired after a restart.
type RecoveryReport struct {
	Found     int
	Recovered []RecoveredInvestigation
}

// RecoveredInvestigation describes a single repaired investigation.
type RecoveredInvestigation struct {
	InvestigationID domain.ID
	PreviousStatus  domain.Status
	NextStatus      domain.Status
	InterruptedRun  int
	InterruptedIDs  []domain.ID
	Note            string
}

// Recover reconciles investigations that were interrupted by a process exit.
//
// It never re-executes commands: non-idempotent work (test runs, patch
// application) may already have happened, so interrupted experiments are
// marked as failed-and-interrupted instead of being replayed. The event and
// evidence history is preserved; only the derived status is repaired so the
// investigation is left in a valid terminal state.
func (i *Investigator) Recover(ctx context.Context) (RecoveryReport, error) {
	report := RecoveryReport{}

	incomplete, err := i.Store.ListIncompleteInvestigations()
	if err != nil {
		return report, err
	}
	report.Found = len(incomplete)

	for _, inv := range incomplete {
		if err := ctx.Err(); err != nil {
			return report, err
		}

		previous := inv.Status
		experiments, err := i.Store.ListExperiments(inv.ID)
		if err != nil {
			return report, err
		}

		var interrupted []domain.ID
		running := 0
		for _, ex := range experiments {
			if ex.Status == domain.StatusRunningExperiment {
				if ex.State == domain.ExperimentRunning {
					if err := i.Store.TransitionExperiment(ex.ID, inv.ID, ex.State, domain.ExperimentFailed, "process restart"); err != nil {
						return report, err
					}
					if inv.Status == domain.StatusGeneratingPatch || inv.Status == domain.StatusVerifyingPatch {
						patches, err := i.Store.ListPatches(inv.ID)
						if err != nil {
							return report, err
						}
						for _, patch := range patches {
							if patch.VerificationStatus == "" || patch.VerificationStatus == string(domain.VerificationInconclusive) {
								patch.VerificationStatus = string(domain.VerificationInconclusive)
								patch.Error = "verification interrupted by process restart; not re-run automatically"
								if err := i.Store.SavePatch(patch); err != nil {
									return report, err
								}
								_ = i.Store.SaveVerificationReport(domain.VerificationReport{
									PatchID: patch.ID, Status: domain.VerificationInconclusive,
									BaseRevision: patch.BaseRevision, CreatedAt: time.Now().UTC(),
									RemainingUncertainty: []string{"verification state was interrupted and requires explicit user restart"},
								})
							}
						}
					}
				}
				ex.Status = domain.StatusEvaluatingEvidence
				ex.Outcome = domain.OutcomeFailed
				ex.State = domain.ExperimentFailed
				ex.Error = "execution interrupted by process restart; not re-run because the command may not be idempotent"
				ex.Evaluation = "interrupted before observation; hypothesis impact is inconclusive"
				ex.FinishedAt = nowPtr()
				if err := i.Store.SaveExperiment(ex); err != nil {
					return report, err
				}
				interrupted = append(interrupted, ex.ID)
				running++
			}
		}

		inv.Status = domain.StatusInconclusive
		inv.UpdatedAt = time.Now().UTC()
		if err := i.Store.SaveInvestigation(inv); err != nil {
			return report, err
		}

		note := "recovered after restart; investigation marked inconclusive"
		if running > 0 {
			note = "recovered after restart; interrupted experiments preserved and not re-run"
		}
		_ = i.recordEvent(inv.ID, previous, inv.Status, "recovered_after_restart", "", "", note)

		slog.Info("recovered interrupted investigation",
			"investigation_id", string(inv.ID),
			"previous_status", string(previous),
			"next_status", string(inv.Status),
			"interrupted_experiments", running)

		report.Recovered = append(report.Recovered, RecoveredInvestigation{
			InvestigationID: inv.ID,
			PreviousStatus:  previous,
			NextStatus:      inv.Status,
			InterruptedRun:  running,
			InterruptedIDs:  interrupted,
			Note:            note,
		})
	}

	return report, nil
}
