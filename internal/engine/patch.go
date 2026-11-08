package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/causent/malenia/internal/domain"
)

const maxPatchBytes = 256 << 10
const maxPatchFiles = 16
const maxPatchLines = 2000
const maxPatchGenerationAttempts = 2
const defaultPatchAttempts = 2

// GenerateAndVerifyPatch creates candidates through the structured provider and
// verifies each candidate in an independent copy of the repository.
func (i *Investigator) GenerateAndVerifyPatch(ctx context.Context, inv domain.Investigation, baseline domain.Reproduction, evidence []domain.Evidence, hypotheses []domain.Hypothesis, experiments []domain.Experiment) (*domain.Patch, error) {
	attempts := i.PatchAttempts
	if attempts <= 0 {
		attempts = defaultPatchAttempts
	}
	if attempts > 5 {
		attempts = 5
	}

	var last *domain.Patch
	feedback := ""
	for attempt := 1; attempt <= attempts; attempt++ {
		patch, err := i.generateAndVerifyPatchOnce(ctx, inv, baseline, evidence, hypotheses, experiments, feedback)
		if err != nil {
			return patch, err
		}
		last = patch
		if patch != nil && patch.VerificationStatus == string(domain.VerificationPassed) {
			return patch, nil
		}
		feedback = patchVerificationFeedback(patch, attempt, attempts)
	}
	return last, nil
}

func (i *Investigator) generateAndVerifyPatchOnce(ctx context.Context, inv domain.Investigation, baseline domain.Reproduction, evidence []domain.Evidence, hypotheses []domain.Hypothesis, experiments []domain.Experiment, feedback string) (*domain.Patch, error) {
	provider, ok := i.Provider.(PatchProvider)
	if !ok && !(i.ProposalEnabled && i.ProposalProvider != nil) {
		return nil, fmt.Errorf("configured model provider does not support patch generation")
	}
	request := PatchRequest{Investigation: inv, Evidence: evidence, Hypotheses: hypotheses, Experiments: experiments, DisallowTestChanges: i.DisallowTestChanges, ValidationError: feedback}
	var proposals []domain.PatchProposal
	var err error
	for attempt := 1; attempt <= maxPatchGenerationAttempts; attempt++ {
		if err != nil {
			request.ValidationError = errString(err)
		}
		if i.ProposalEnabled && i.ProposalProvider != nil {
			var output ProposalOutput
			output, err = i.ProposalProvider.Propose(ctx, ProposalInput{
				Command: inv.Command, Diagnosis: proposalDiagnosis(hypotheses),
				Evidence: evidence, PriorFeedback: request.ValidationError,
			})
			if err == nil {
				err = ValidateProposal(ProposalInput{Command: inv.Command, Diagnosis: proposalDiagnosis(hypotheses), Evidence: evidence}, output)
			}
			if err == nil {
				proposals = []domain.PatchProposal{{Diff: output.Patch, ChangedFiles: output.ChangedPaths, Explanation: output.Rationale, ExpectedBehavior: "satisfy the diagnosed failing use case", Risks: output.Limitations, Metadata: domain.ModelMetadata{Provider: "proposal"}}}
			}
		} else {
			proposals, err = provider.GeneratePatches(ctx, request)
		}
		if err != nil {
			return nil, err
		}

		if len(proposals) == 0 {
			err = fmt.Errorf("provider returned no patch proposals")
		} else {
			if i.DisallowTestChanges {
				err = validateStructuredEditTargets(proposals[0])
			}
			if err == nil {
				err = materializeStructuredEdits(inv, &proposals[0])
			}
			if err == nil {
				err = validatePatchProposal(inv, hypotheses, proposals[0], i.DisallowTestChanges)
			}
		}

		if err == nil {
			break
		}
		if attempt == maxPatchGenerationAttempts {
			return nil, fmt.Errorf("patch generation failed after %d attempts: %w", attempt, err)
		}
	}
	p := proposals[0]
	now := time.Now().UTC()
	patch := domain.Patch{ID: newID(), InvestigationID: inv.ID, Diff: p.Diff, Status: domain.PatchValidated, CreatedAt: now,
		HypothesisIDs: p.HypothesisIDs, Explanation: p.Explanation, ExpectedBehavior: p.ExpectedBehavior,
		ChangedFiles: p.ChangedFiles, Digest: patchDigest(p.Diff), Provider: p.Metadata, ValidationStatus: "validated"}
	patch.BaseRevision = gitRevision(inv.RepoPath)
	if patch.BaseRevision == "" {
		return nil, fmt.Errorf("could not determine repository base revision")
	}
	if gitRevision(inv.RepoPath) != patch.BaseRevision {
		return nil, fmt.Errorf("repository changed after candidate base revision was captured")
	}
	if err := i.Store.SavePatch(patch); err != nil {
		return nil, err
	}
	if i.ProposalEnabled && i.ProposalProvider != nil {
		baselineResult, reproducible, baselineErr := i.reproduceVerificationBaseline(ctx, inv, baseline)
		if baselineErr != nil {
			return &patch, baselineErr
		}
		baseline.Result = baselineResult
		if !reproducible {
			report := domain.VerificationReport{PatchID: patch.ID, BaseRevision: patch.BaseRevision, Baseline: baselineResult, Status: domain.VerificationInconclusive, CreatedAt: now,
				RemainingUncertainty: []string{"baseline failure was not reproducible across verification attempts"}}
			patch.VerificationStatus = string(report.Status)
			patch.VerificationReport = string(report.Status)
			_ = i.Store.SaveVerificationReport(report)
			_ = i.Store.SavePatch(patch)
			return &patch, nil
		}
	}
	for _, alternative := range proposals[1:] {
		if i.DisallowTestChanges {
			if err := validateStructuredEditTargets(alternative); err != nil {
				return &patch, fmt.Errorf("invalid alternative patch proposal: %w", err)
			}
		}
		if err := materializeStructuredEdits(inv, &alternative); err != nil {
			return &patch, err
		}
		if err := validatePatchProposal(inv, hypotheses, alternative, i.DisallowTestChanges); err != nil {
			return &patch, fmt.Errorf("invalid alternative patch proposal: %w", err)
		}
		alternativePatch := domain.Patch{
			ID: newID(), InvestigationID: inv.ID, Diff: alternative.Diff, Status: domain.PatchValidated,
			CreatedAt: now, HypothesisIDs: alternative.HypothesisIDs, Explanation: alternative.Explanation,
			ExpectedBehavior: alternative.ExpectedBehavior, ChangedFiles: alternative.ChangedFiles,
			Digest: patchDigest(alternative.Diff), BaseRevision: patch.BaseRevision, Provider: alternative.Metadata,
			ValidationStatus: "validated", VerificationStatus: string(domain.VerificationInconclusive),
		}
		if err := i.Store.SavePatch(alternativePatch); err != nil {
			return &patch, err
		}
	}
	workspace, err := copyWorkspace(inv.RepoPath)
	if err != nil {
		return &patch, err
	}
	defer os.RemoveAll(workspace)
	patch.WorkspacePath = workspace
	patch.ApplicationStatus = "applying"
	if patchDigest(patch.Diff) != patch.Digest {
		patch.ApplicationStatus = "failed"
		patch.Error = "patch digest mismatch before application"
		patch.Status = domain.PatchDoesNotApply
		_ = i.Store.SavePatch(patch)
		return &patch, fmt.Errorf("patch digest mismatch before application")
	}
	if err := applyPatch(workspace, p.Diff); err != nil {
		patch.ApplicationStatus = "failed"
		patch.Error = err.Error()
		patch.Status = domain.PatchDoesNotApply
		_ = i.Store.SavePatch(patch)
		return &patch, err
	}
	patch.ApplicationStatus = "applied"
	result, runErr := i.Executor.Run(ctx, domain.ExecutionRequest{Command: inv.Command, Dir: workspace, Timeout: 5 * time.Second, MaxOutput: 64 << 10})
	report := domain.VerificationReport{PatchID: patch.ID, BaseRevision: patch.BaseRevision, Baseline: baseline.Result, OriginalAfterPatch: &result, CreatedAt: now, OriginalResolved: runErr == nil && result.ExitCode == 0, RegressionsPassed: true}
	if baseline.Result == nil {
		report.RemainingUncertainty = append(report.RemainingUncertainty, "baseline result was unavailable")
		report.Status = domain.VerificationInconclusive
	}
	if art, err := i.Store.SaveArtifact(inv.ID, "patch-original-output", []byte(result.Stdout+"\n"+result.Stderr)); err == nil {
		report.EvidenceIDs = append(report.EvidenceIDs, art.ID)
	}
	regressionCommands := selectRegressionCommands(inv, p.ChangedFiles)
	for _, command := range regressionCommands {
		regression, err := i.Executor.Run(ctx, domain.ExecutionRequest{Command: command, Dir: workspace, Timeout: 5 * time.Second, MaxOutput: 64 << 10})
		if err != nil {
			report.RegressionsPassed = false
			report.RemainingUncertainty = append(report.RemainingUncertainty, "a regression test could not complete")
		}
		report.RegressionResults = append(report.RegressionResults, regression)
		patch.RegressionResults = append(patch.RegressionResults, regression)
		if regression.ExitCode != 0 || regression.TimedOut {
			report.RegressionsPassed = false
		}
		if art, err := i.Store.SaveArtifact(inv.ID, "patch-regression-output", []byte(regression.Stdout+"\n"+regression.Stderr)); err == nil {
			report.EvidenceIDs = append(report.EvidenceIDs, art.ID)
		}
	}
	report.RootCauseVerified = false
	if runErr != nil {
		if ctx.Err() != nil {
			report.Status = domain.VerificationCancelled
		} else {
			report.Status = domain.VerificationError
		}
		report.ApplicationError = runErr.Error()
	} else if report.OriginalResolved && report.RegressionsPassed {
		report.Status = domain.VerificationPassed
		patch.Status = domain.PatchValidated
		report.RemainingUncertainty = append(report.RemainingUncertainty, "passing tests verify behavior, not root-cause certainty")
	} else if report.OriginalResolved {
		report.Status = domain.VerificationFailed
		patch.Status = domain.PatchFailsOriginal
	} else {
		report.Status = domain.VerificationFailed
		patch.Status = domain.PatchFailsOriginal
	}

	patch.VerificationStatus = string(report.Status)
	patch.VerifiedAt = &now
	patch.OriginalTestResult = &result
	patch.VerificationReport = string(report.Status)
	if err := os.RemoveAll(workspace); err != nil {
		patch.ApplicationStatus = "cleanup_failed"
		patch.Error = fmt.Sprintf("candidate workspace cleanup failed: %v", err)
	} else {
		patch.ApplicationStatus = "cleaned"
		patch.WorkspacePath = ""
	}
	_ = i.Store.SaveVerificationReport(report)
	if err := i.Store.SavePatch(patch); err != nil {
		return &patch, err
	}
	return &patch, nil
}

func (i *Investigator) reproduceVerificationBaseline(ctx context.Context, inv domain.Investigation, recorded domain.Reproduction) (*domain.ExecutionResult, bool, error) {
	attempts := 2
	if recorded.Result != nil && recorded.Result.TimedOut {
		// A timeout is still a failure, but it must be reproduced as a timeout.
		attempts = 2
	}
	var last *domain.ExecutionResult
	for n := 0; n < attempts; n++ {
		workspace, err := copyWorkspace(inv.RepoPath)
		if err != nil {
			return nil, false, err
		}
		result, runErr := i.Executor.Run(ctx, domain.ExecutionRequest{Command: inv.Command, Dir: workspace, Timeout: 5 * time.Second, MaxOutput: 64 << 10})
		_ = os.RemoveAll(workspace)
		if runErr != nil && ctx.Err() != nil {
			return &result, false, runErr
		}
		last = &result
		failed := result.ExitCode != 0 || result.TimedOut
		expectedTimeout := recorded.Result != nil && recorded.Result.TimedOut
		if !failed || result.TimedOut != expectedTimeout {
			return last, false, nil
		}
	}
	return last, true, nil
}

func proposalDiagnosis(hypotheses []domain.Hypothesis) string {
	var b strings.Builder
	for _, hypothesis := range hypotheses {
		fmt.Fprintf(&b, "%s\n", bounded(hypothesis.Statement, 2000))
	}
	return bounded(b.String(), 6000)
}

func patchVerificationFeedback(patch *domain.Patch, attempt, limit int) string {
	if patch == nil {
		return fmt.Sprintf("previous patch attempt %d/%d did not produce a candidate", attempt, limit)
	}
	feedback := fmt.Sprintf("previous patch attempt %d/%d was not verified: status=%s verification=%s", attempt, limit, patch.Status, patch.VerificationStatus)
	if patch.Error != "" {
		feedback += "; error=" + bounded(patch.Error, 4000)
	}
	if patch.OriginalTestResult != nil {
		feedback += fmt.Sprintf("; verification exit_code=%d timed_out=%t", patch.OriginalTestResult.ExitCode, patch.OriginalTestResult.TimedOut)
		output := bounded(strings.TrimSpace(patch.OriginalTestResult.Stdout+"\n"+patch.OriginalTestResult.Stderr), 6000)
		if output != "" {
			feedback += "\nverification output:\n" + output
		}
	}
	return feedback
}

// CancelPatch records cancellation without fabricating a verification result.
func (i *Investigator) CancelPatch(id domain.ID) error {
	patch, err := i.Store.GetPatch(id)
	if err != nil {
		return err
	}
	if patch.VerificationStatus == string(domain.VerificationPassed) || patch.VerificationStatus == string(domain.VerificationFailed) {
		return fmt.Errorf("patch verification is already terminal")
	}
	now := time.Now().UTC()
	patch.VerificationStatus = string(domain.VerificationCancelled)
	patch.Error = "verification cancelled"
	if err := i.Store.SavePatch(patch); err != nil {
		return err
	}
	return i.Store.SaveVerificationReport(domain.VerificationReport{
		PatchID: id, Status: domain.VerificationCancelled, BaseRevision: patch.BaseRevision,
		CreatedAt: now, RemainingUncertainty: []string{"verification was cancelled before a complete result was available"},
	})
}

func selectRegressionCommands(inv domain.Investigation, _ []string) [][]string {
	if len(inv.Command) == 0 {
		return nil
	}
	var selected [][]string
	_ = filepath.Walk(inv.RepoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() || len(selected) >= 3 || filepath.Ext(path) != ".py" {
			return nil
		}
		name := filepath.Base(path)
		if !strings.HasPrefix(name, "test_") && !strings.HasSuffix(name, "_test.py") {
			return nil
		}
		rel, err := filepath.Rel(inv.RepoPath, path)
		if err != nil {
			return nil
		}
		for _, arg := range inv.Command[1:] {
			if filepath.Clean(arg) == filepath.Clean(rel) {
				return nil
			}
		}
		cmd := append([]string(nil), inv.Command...)
		if len(cmd) >= 2 {
			cmd[len(cmd)-1] = filepath.ToSlash(rel)
		} else {
			cmd = []string{"python3", filepath.ToSlash(rel)}
		}
		selected = append(selected, cmd)
		return nil
	})
	sort.SliceStable(selected, func(a, b int) bool { return strings.Join(selected[a], "\x00") < strings.Join(selected[b], "\x00") })
	return selected
}

// ComparePatches orders candidates by observed verification outcomes and
// records the trade-offs; it never treats provider confidence as proof.
func (i *Investigator) ComparePatches(invID domain.ID) (domain.PatchComparison, error) {
	patches, err := i.Store.ListPatches(invID)
	if err != nil {
		return domain.PatchComparison{}, err
	}
	comparison := domain.PatchComparison{InvestigationID: invID, Reasons: map[domain.ID][]string{}, CreatedAt: time.Now().UTC()}
	type scored struct {
		id    domain.ID
		score int
	}
	scores := make([]scored, 0, len(patches))
	for _, patch := range patches {
		comparison.PatchIDs = append(comparison.PatchIDs, patch.ID)
		score := 0
		if patch.VerificationStatus == string(domain.VerificationPassed) {
			score += 4
			comparison.Reasons[patch.ID] = append(comparison.Reasons[patch.ID], "original failure resolved and selected regressions passed")
		} else {
			comparison.Reasons[patch.ID] = append(comparison.Reasons[patch.ID], "verification did not establish a passing candidate")
		}
		if len(patch.ChangedFiles) <= 1 {
			score++
			comparison.Reasons[patch.ID] = append(comparison.Reasons[patch.ID], "small change surface")
		}
		if report, err := i.Store.GetVerificationReport(patch.ID); err == nil && report.RootCauseVerified {
			score++
		} else {
			comparison.Reasons[patch.ID] = append(comparison.Reasons[patch.ID], "root cause remains independently unverified")
		}
		scores = append(scores, scored{patch.ID, score})
	}
	sort.SliceStable(scores, func(a, b int) bool { return scores[a].score > scores[b].score })
	for _, item := range scores {
		comparison.Ranked = append(comparison.Ranked, item.id)
	}
	return comparison, nil
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func materializeStructuredEdits(inv domain.Investigation, proposal *domain.PatchProposal) error {
	if proposal.Diff != "" || len(proposal.Edits) == 0 {
		return nil
	}
	if len(proposal.Edits) != 1 {
		return fmt.Errorf("structured patch must contain exactly one edit")
	}
	edit := proposal.Edits[0]
	if filepath.IsAbs(edit.File) || filepath.Clean(edit.File) == "." || strings.HasPrefix(filepath.Clean(edit.File), "..") {
		return fmt.Errorf("edit path escapes repository: %q", edit.File)
	}
	path := filepath.Join(inv.RepoPath, edit.File)
	source, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read edit target %q: %w", edit.File, err)
	}
	if edit.OldText == "" {
		return fmt.Errorf("edit old_text is empty")
	}
	if strings.Count(string(source), edit.OldText) != 1 {
		return fmt.Errorf("edit old_text must match exactly once in %q", edit.File)
	}
	updated := strings.Replace(string(source), edit.OldText, edit.NewText, 1)
	tmp, err := os.MkdirTemp("", "malenia-edit-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	oldPath := filepath.Join(tmp, "old")
	newPath := filepath.Join(tmp, "new")
	if err := os.WriteFile(oldPath, source, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(newPath, []byte(updated), 0600); err != nil {
		return err
	}
	out, _ := exec.Command("git", "diff", "--no-index", "--unified=3", oldPath, newPath).Output()
	lines := strings.Split(string(out), "\n")
	oldHeader, newHeader := -1, -1
	for idx, line := range lines {
		if strings.HasPrefix(line, "--- ") && oldHeader < 0 {
			oldHeader = idx
		}
		if strings.HasPrefix(line, "+++ ") && newHeader < 0 {
			newHeader = idx
		}
	}
	if oldHeader < 0 || newHeader < 0 {
		return fmt.Errorf("structured edit produced no diff")
	}
	lines[oldHeader] = "--- a/" + filepath.ToSlash(edit.File)
	lines[newHeader] = "+++ b/" + filepath.ToSlash(edit.File)
	proposal.Diff = strings.Join(lines, "\n")
	proposal.ChangedFiles = []string{filepath.ToSlash(edit.File)}
	return nil
}

func validateStructuredEditTargets(proposal domain.PatchProposal) error {
	for _, edit := range proposal.Edits {
		if isTestFile(edit.File) {
			return fmt.Errorf("benchmark policy disallows changing test file %q; edit the implementation file imported by the failing test", edit.File)
		}
	}
	for _, file := range proposal.ChangedFiles {
		if isTestFile(file) {
			return fmt.Errorf("benchmark policy disallows changing test file %q; edit the implementation file imported by the failing test", file)
		}
	}
	return nil
}

func isTestFile(file string) bool {
	name := strings.ToLower(filepath.Base(file))
	return strings.HasPrefix(name, "test_") || strings.HasSuffix(name, "_test.py") || strings.HasSuffix(name, "_test.go")
}

func validatePatchProposal(inv domain.Investigation, hypotheses []domain.Hypothesis, p domain.PatchProposal, disallowTestChanges ...bool) error {
	if strings.TrimSpace(p.Diff) == "" || len(p.Diff) > maxPatchBytes {
		return fmt.Errorf("patch diff is empty or exceeds size limit")
	}
	known := map[domain.ID]bool{}
	for _, h := range hypotheses {
		known[h.ID] = true
	}
	for _, id := range p.HypothesisIDs {
		if !known[id] {
			return fmt.Errorf("patch references unknown hypothesis %s", id)
		}
	}
	if len(p.ChangedFiles) == 0 {
		return fmt.Errorf("patch has no changed files")
	}
	for _, file := range p.ChangedFiles {
		if len(disallowTestChanges) > 0 && disallowTestChanges[0] {
			if isTestFile(file) {
				return fmt.Errorf("benchmark policy disallows changing test file %q; edit the implementation file imported by the failing test", file)
			}
		}
		if filepath.IsAbs(file) || filepath.Clean(file) == "." || strings.HasPrefix(filepath.Clean(file), "..") {
			return fmt.Errorf("patch path escapes repository: %q", file)
		}
		if !strings.Contains(p.Diff, "a/"+filepath.ToSlash(file)) || !strings.Contains(p.Diff, "b/"+filepath.ToSlash(file)) {
			return fmt.Errorf("diff does not target declared file %q", file)
		}
		if _, err := os.Stat(filepath.Join(inv.RepoPath, file)); err != nil {
			return fmt.Errorf("patch target does not exist: %q", file)
		}
	}
	if !strings.Contains(p.Diff, "--- ") || !strings.Contains(p.Diff, "+++ ") {
		return fmt.Errorf("malformed unified diff")
	}
	if err := validateParsedPatch(p.Diff, p.ChangedFiles, disallowTestChanges...); err != nil {
		return err
	}
	return nil
}

// validateParsedPatch derives paths and operations from the patch itself. The
// model's ChangedFiles is only an assertion that must agree with this result.
func validateParsedPatch(diff string, declared []string, disallowTestChanges ...bool) error {
	declaredSet := make(map[string]bool, len(declared))
	for _, path := range declared {
		declaredSet[filepath.ToSlash(filepath.Clean(path))] = true
	}
	actual := map[string]bool{}
	lines := strings.Split(diff, "\n")
	changedLines := 0
	symlink := false
	for _, line := range lines {
		if strings.HasPrefix(line, "Binary files ") || strings.HasPrefix(line, "GIT binary patch") {
			return fmt.Errorf("binary patches are not allowed")
		}
		if strings.Contains(line, "mode 120000") || strings.HasPrefix(line, "new file mode 120000") || strings.HasPrefix(line, "old mode 120000") {
			symlink = true
		}
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") || strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---") {
			changedLines++
		}
		for _, prefix := range []string{"--- a/", "+++ b/"} {
			if strings.HasPrefix(line, prefix) {
				path := filepath.ToSlash(filepath.Clean(strings.TrimSpace(strings.TrimPrefix(line, prefix))))
				if path == "." || path == "" || filepath.IsAbs(path) || path == ".." || strings.HasPrefix(path, "../") {
					return fmt.Errorf("patch path escapes repository: %q", path)
				}
				actual[path] = true
			}
		}
	}
	if symlink {
		return fmt.Errorf("symlink creation or modification is not allowed")
	}
	if len(actual) == 0 {
		return fmt.Errorf("patch contains no parsed file operations")
	}
	if len(actual) > maxPatchFiles {
		return fmt.Errorf("patch changes %d files; maximum is %d", len(actual), maxPatchFiles)
	}
	if changedLines > maxPatchLines {
		return fmt.Errorf("patch changes %d lines; maximum is %d", changedLines, maxPatchLines)
	}
	for path := range actual {
		if !declaredSet[path] {
			return fmt.Errorf("parsed patch path %q was not declared", path)
		}
		if sensitivePatchPath(path) {
			return fmt.Errorf("patch changes sensitive path %q", path)
		}
		if len(disallowTestChanges) > 0 && disallowTestChanges[0] && isTestFile(path) {
			return fmt.Errorf("benchmark policy disallows changing test file %q", path)
		}
	}
	for path := range declaredSet {
		if !actual[path] {
			return fmt.Errorf("declared path %q is absent from parsed patch", path)
		}
	}
	return nil
}

func sensitivePatchPath(path string) bool {
	clean := filepath.ToSlash(filepath.Clean(path))
	parts := strings.Split(clean, "/")
	if len(parts) > 0 && parts[0] == ".github" {
		return true
	}
	base := strings.ToLower(filepath.Base(clean))
	for _, marker := range []string{"lock", "dockerfile", "makefile", ".github", "jenkinsfile", ".gitlab-ci"} {
		if strings.Contains(base, marker) {
			return true
		}
	}
	for _, dir := range []string{"scripts", "ci", "deploy", "deployment", ".buildkite"} {
		for _, part := range parts {
			if strings.EqualFold(part, dir) {
				return true
			}
		}
	}
	return false
}

func patchDigest(diff string) string {
	sum := sha256.Sum256([]byte(diff))
	return hex.EncodeToString(sum[:])
}

func gitRevision(repo string) string {
	out, err := exec.Command("git", "-C", repo, "rev-parse", "HEAD").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func copyWorkspace(repo string) (string, error) {
	dst, err := os.MkdirTemp("", "malenia-candidate-*")
	if err != nil {
		return "", err
	}
	err = filepath.Walk(repo, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info == nil {
			return fmt.Errorf("workspace entry has no metadata: %s", path)
		}
		rel, err := filepath.Rel(repo, path)
		if err != nil || rel == "." || rel == ".git" || strings.HasPrefix(rel, ".git"+string(filepath.Separator)) {
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("workspace contains unsupported symlink: %s", rel)
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode())
	})
	if err != nil {
		_ = os.RemoveAll(dst)
		return "", err
	}
	if err := exec.Command("git", "-C", dst, "init", "-q").Run(); err != nil {
		_ = os.RemoveAll(dst)
		return "", fmt.Errorf("initialize candidate workspace: %w", err)
	}
	return dst, nil
}

func applyPatch(workspace, diff string) error {
	file, err := os.CreateTemp("", "malenia-patch-*.diff")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if _, err := file.WriteString(diff); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if out, err := exec.Command("git", "-C", workspace, "apply", "--check", name).CombinedOutput(); err != nil {
		return fmt.Errorf("patch check failed: %s", strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("git", "-C", workspace, "apply", name).CombinedOutput(); err != nil {
		return fmt.Errorf("patch application failed: %s", strings.TrimSpace(string(out)))
	}
	return nil
}
