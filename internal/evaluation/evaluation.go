package evaluation

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Yashbhu/Hades/internal/domain"
	"github.com/Yashbhu/Hades/internal/engine"
	"github.com/Yashbhu/Hades/internal/execution"
	"github.com/Yashbhu/Hades/internal/persistence"
)

type Config struct {
	Suite         domain.BenchmarkSuite
	Strategies    []domain.EvaluationStrategy
	Budget        int
	Timeout       time.Duration
	PromptVersion string
	Model         domain.ModelMetadata
	Provider      engine.ModelProvider
	Executor      execution.Executor
	Store         *persistence.Store
}

func ValidateSuite(suite domain.BenchmarkSuite) error {
	if strings.TrimSpace(suite.ID) == "" || strings.TrimSpace(suite.Version) == "" {
		return fmt.Errorf("suite ID and version are required")
	}
	seen := map[string]bool{}
	for _, c := range suite.Cases {
		if c.ID == "" || seen[c.ID] {
			return fmt.Errorf("duplicate or empty benchmark case ID: %q", c.ID)
		}
		seen[c.ID] = true
		if c.SuiteID != suite.ID || c.Version == "" || len(c.ReproductionCommand) == 0 {
			return fmt.Errorf("invalid benchmark case %q metadata", c.ID)
		}
		if c.RepoPath == "" || c.BuggyRevision == "" || c.KnownGoodRevision == "" || c.RootCause == "" {
			return fmt.Errorf("benchmark case %q is missing pinned repository or ground truth metadata", c.ID)
		}
		if _, err := os.Stat(c.RepoPath); err != nil {
			return fmt.Errorf("benchmark case %q repository: %w", c.ID, err)
		}
	}
	return nil
}

func LoadSuite(path string) (domain.BenchmarkSuite, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return domain.BenchmarkSuite{}, err
	}
	var suite domain.BenchmarkSuite
	if err := json.Unmarshal(data, &suite); err != nil {
		return suite, err
	}
	if err := ValidateSuite(suite); err != nil {
		return suite, err
	}
	return suite, nil
}

func RunSuite(ctx context.Context, cfg Config) (domain.EvaluationSummary, error) {
	if err := ValidateSuite(cfg.Suite); err != nil {
		return domain.EvaluationSummary{}, err
	}
	if len(cfg.Strategies) == 0 {
		cfg.Strategies = []domain.EvaluationStrategy{domain.StrategyDirectRepair, domain.StrategyEvidenceGuided}
	}
	if cfg.Budget <= 0 {
		cfg.Budget = 20
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Minute
	}
	evaluationID := persistence.NewID()
	if err := cfg.Store.SaveBenchmarkSuite(cfg.Suite); err != nil {
		return domain.EvaluationSummary{}, err
	}
	for _, c := range cfg.Suite.Cases {
		if err := cfg.Store.SaveBenchmarkCase(c); err != nil {
			return domain.EvaluationSummary{}, err
		}
	}
	for _, c := range cfg.Suite.Cases {
		for _, strategy := range cfg.Strategies {
			trial := runTrial(ctx, evaluationID, cfg, c, strategy)
			if err := cfg.Store.SaveEvaluationTrial(trial); err != nil {
				return domain.EvaluationSummary{}, err
			}
		}
	}
	trials, err := cfg.Store.ListEvaluationTrials(evaluationID)
	if err != nil {
		return domain.EvaluationSummary{}, err
	}
	summary := Summarize(evaluationID, cfg.Suite, trials)
	if err := cfg.Store.SaveEvaluationSummary(summary); err != nil {
		return domain.EvaluationSummary{}, err
	}
	return summary, nil
}

func runTrial(ctx context.Context, evaluationID domain.ID, cfg Config, c domain.BenchmarkCase, strategy domain.EvaluationStrategy) domain.EvaluationTrial {
	start := time.Now().UTC()
	trial := domain.EvaluationTrial{ID: domain.ID(fmt.Sprintf("%s-%s-%s", start.Format("20060102T150405.000000000"), c.ID, strategy)), EvaluationID: evaluationID, SuiteID: cfg.Suite.ID, SuiteVersion: cfg.Suite.Version, CaseID: c.ID, Strategy: strategy, Model: cfg.Model, PromptVersion: cfg.PromptVersion, BuggyRevision: c.BuggyRevision, KnownGoodRevision: c.KnownGoodRevision, BudgetSteps: cfg.Budget, Timeout: cfg.Timeout, StartedAt: start, Outcome: domain.EvaluationIncomplete}
	trialRepo, prepErr := prepareTrialRepository(c.RepoPath)
	if prepErr != nil {
		trial.Error = prepErr.Error()
		trial.IncompleteStage = "infrastructure"
		finished := time.Now().UTC()
		trial.FinishedAt = &finished
		trial.ExecutionTime = finished.Sub(start)
		return trial
	}
	defer os.RemoveAll(trialRepo)
	c.RepoPath = trialRepo
	inv := domain.Investigation{ID: trial.ID, RepoPath: c.RepoPath, Command: c.ReproductionCommand, CreatedAt: start, UpdatedAt: start}
	investigator := &engine.Investigator{Store: cfg.Store, Executor: cfg.Executor, Provider: cfg.Provider, Model: cfg.Model, DisallowTestChanges: true}
	var result domain.DiagnosisResult
	var err error
	if strategy == domain.StrategyEvidenceOnly || strategy == domain.StrategyHypothesesOnly {
		rep, repErr := reproduce(ctx, cfg.Executor, c, cfg.Timeout)
		if repErr != nil {
			err = repErr
		} else if !rep.Reproducible {
			trial.IncompleteStage = "reproduction"
			err = fmt.Errorf("benchmark failure was not reproduced")
		} else if strategy == domain.StrategyHypothesesOnly {
			trial.ModelCalls = 1
			if cfg.Provider == nil {
				err = fmt.Errorf("provider is required for hypothesis ablation")
			} else {
				response, modelErr := cfg.Provider.Generate(ctx, engine.ModelRequest{InvestigationID: trial.ID, Context: fmt.Sprintf("BENCHMARK CASE %s\nFAILURE %s\nSTDERR %s\n", c.ID, c.ExpectedFailure, rep.Result.Stderr)})
				if modelErr != nil {
					err = modelErr
				} else {
					trial.HypothesisPrecision = boolFloat(len(response.Hypotheses) > 0)
					trial.RootCauseCorrect = anyHypothesisMatches(c.RootCause, response.Hypotheses)
					trial.IncompleteStage = "hypothesis_generation_only"
					trial.Outcome = domain.EvaluationIncomplete
				}

			}
		} else {
			trial.IncompleteStage = "evidence_collection_only"
			trial.Outcome = domain.EvaluationIncomplete
		}
	} else if strategy == domain.StrategyEvidenceGuided {
		trial.ModelCalls = 2
		_, result, err = investigator.Investigate(ctx, c.RepoPath, c.ReproductionCommand, cfg.Timeout, cfg.Budget)
	} else {
		trial.ModelCalls = 1
		rep, repErr := reproduce(ctx, cfg.Executor, c, cfg.Timeout)
		if repErr != nil {
			err = repErr
		} else {
			if saveErr := cfg.Store.SaveInvestigation(inv); saveErr != nil {
				err = saveErr
			} else {
				patch, patchErr := investigator.GenerateAndVerifyPatch(ctx, inv, rep, nil, nil, nil)
				if patchErr != nil {
					err = patchErr
				} else {
					result.InvestigationID = inv.ID
					result.Patch = patch
					result.Reproduction = &rep
				}
			}
		}
	}
	if err != nil {
		trial.Error = err.Error()
		trial.InvestigationID = result.InvestigationID
		trial.PatchID = patchID(result.Patch)
		trial.Experiments = result.ExperimentCount
		trial.RootCauseCorrect = rootCauseMatch(c.RootCause, result.FinalReport)
		if result.Patch != nil {
			trial.RootCauseCorrect = trial.RootCauseCorrect || rootCauseMatch(c.RootCause, result.Patch.Explanation)
		}
		if result.HypothesisCount > 0 {
			trial.HypothesisPrecision = 1
			trial.HypothesisRecall = boolFloat(trial.RootCauseCorrect)
		}
		if strings.Contains(strings.ToLower(trial.Error), "not authorized") ||
			strings.Contains(strings.ToLower(trial.Error), "outside allowed") ||
			strings.Contains(strings.ToLower(trial.Error), "repository") {
			trial.IncompleteStage = "infrastructure"
		}
		if ctx.Err() != nil {
			trial.Outcome = domain.EvaluationTimeout
			trial.IncompleteStage = "execution"
		} else {
			trial.Outcome = domain.EvaluationFailure
		}
	} else {
		trial.InvestigationID = result.InvestigationID
		trial.PatchID = patchID(result.Patch)
		trial.OriginalResolved = result.Patch != nil && result.Patch.VerificationStatus == string(domain.VerificationPassed)
		trial.RegressionFree = trial.OriginalResolved
		trial.Experiments = result.ExperimentCount
		trial.RootCauseCorrect = rootCauseMatch(c.RootCause, result.FinalReport)
		if result.Patch != nil {
			trial.RootCauseCorrect = trial.RootCauseCorrect || rootCauseMatch(c.RootCause, result.Patch.Explanation)
		}
		if result.HypothesisCount > 0 {
			trial.HypothesisPrecision = 1
			trial.HypothesisRecall = boolFloat(trial.RootCauseCorrect)
		}
		if trial.OriginalResolved {
			trial.Outcome = domain.EvaluationSuccess
		} else {
			trial.Outcome = domain.EvaluationFailure
		}

	}
	finished := time.Now().UTC()
	trial.FinishedAt = &finished
	trial.ExecutionTime = finished.Sub(start)
	return trial
}

func prepareTrialRepository(source string) (string, error) {
	info, err := os.Stat(source)
	if err != nil {
		return "", fmt.Errorf("benchmark repository: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("benchmark repository is not a directory: %s", source)
	}
	destination, err := os.MkdirTemp("", "hades-eval-repo-*")
	if err != nil {
		return "", fmt.Errorf("create trial repository: %w", err)
	}
	if err := filepath.Walk(source, func(path string, fileInfo os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		if relative == ".git" || strings.HasPrefix(relative, ".git"+string(filepath.Separator)) {
			if fileInfo.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		target := filepath.Join(destination, relative)
		if fileInfo.IsDir() {
			return os.MkdirAll(target, fileInfo.Mode().Perm())
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, fileInfo.Mode().Perm())
	}); err != nil {
		os.RemoveAll(destination)
		return "", fmt.Errorf("copy benchmark repository: %w", err)
	}
	runGit := func(args ...string) error {
		command := exec.Command("git", args...)
		command.Dir = destination
		if output, err := command.CombinedOutput(); err != nil {
			return fmt.Errorf("git %s: %v: %s", args[0], err, strings.TrimSpace(string(output)))
		}
		return nil
	}
	if err := runGit("init", "-q"); err != nil {
		os.RemoveAll(destination)
		return "", err
	}
	if err := runGit("add", "."); err != nil {
		os.RemoveAll(destination)
		return "", err
	}
	if err := runGit("-c", "user.email=hades-evaluation@example.invalid", "-c", "user.name=Hades Evaluation", "commit", "-qm", "benchmark fixture"); err != nil {
		os.RemoveAll(destination)
		return "", err
	}
	return destination, nil
}

func rootCauseMatch(expected, observed string) bool {
	expected = strings.ToLower(expected)
	observed = strings.ToLower(observed)
	words := strings.FieldsFunc(expected, func(r rune) bool { return r == ' ' || r == '_' || r == '-' || r == '/' })
	matches := 0
	for _, word := range words {
		if len(word) >= 4 && strings.Contains(observed, word) {
			matches++
		}
	}
	meaningful := 0
	for _, word := range words {
		if len(word) >= 4 {
			meaningful++
		}
	}
	return meaningful > 0 && matches*2 >= meaningful
}

func boolFloat(value bool) float64 {
	if value {
		return 1
	}
	return 0
}

func anyHypothesisMatches(expected string, hypotheses []engine.ModelHypothesis) bool {
	for _, h := range hypotheses {
		if rootCauseMatch(expected, h.Statement) {
			return true
		}
	}
	return false
}

func reproduce(ctx context.Context, executor execution.Executor, c domain.BenchmarkCase, timeout time.Duration) (domain.Reproduction, error) {
	result, err := executor.Run(ctx, domain.ExecutionRequest{Command: c.ReproductionCommand, Dir: c.RepoPath, Timeout: timeout, MaxOutput: 64 << 10})
	if err != nil {
		return domain.Reproduction{}, err
	}
	return domain.Reproduction{Result: &result, Reproducible: result.ExitCode != 0, Reason: "benchmark reproduction command"}, nil
}

func patchID(p *domain.Patch) domain.ID {
	if p == nil {
		return ""
	}
	return p.ID
}

func Summarize(id domain.ID, suite domain.BenchmarkSuite, trials []domain.EvaluationTrial) domain.EvaluationSummary {
	s := domain.EvaluationSummary{EvaluationID: id, SuiteID: suite.ID, SuiteVersion: suite.Version, Trials: len(trials), ByStrategy: map[domain.EvaluationStrategy]domain.EvaluationSummary{}, CreatedAt: time.Now().UTC()}
	durations := make([]time.Duration, 0, len(trials))
	for _, t := range trials {
		if t.FinishedAt != nil {
			s.Completed++
			durations = append(durations, t.ExecutionTime)
		}
		if t.Outcome == domain.EvaluationSuccess {
			s.Successes++
		}
		if t.OriginalResolved {
			s.OriginalResolved++
		}
		if t.RegressionFree {
			s.RegressionFree++
		}
		if t.RootCauseCorrect {
			s.RootCauseCorrect++
		}
		s.MeanExperiments += float64(t.Experiments)
		s.MeanModelCalls += float64(t.ModelCalls)
		b := s.ByStrategy[t.Strategy]
		b.Trials++
		if t.FinishedAt != nil {
			b.Completed++
			b.MeanDuration += t.ExecutionTime
		}
		if t.Outcome == domain.EvaluationSuccess {
			b.Successes++
		}
		if t.OriginalResolved {
			b.OriginalResolved++
		}
		if t.RegressionFree {
			b.RegressionFree++
		}
		if t.RootCauseCorrect {
			b.RootCauseCorrect++
		}
		b.MeanExperiments += float64(t.Experiments)
		b.MeanModelCalls += float64(t.ModelCalls)
		s.ByStrategy[t.Strategy] = b
	}
	if s.Trials > 0 {
		s.SuccessRate = float64(s.Successes) / float64(s.Trials)
		s.RegressionRate = float64(s.RegressionFree) / float64(s.Trials)
		s.RootCauseAccuracy = float64(s.RootCauseCorrect) / float64(s.Trials)
		s.MeanExperiments /= float64(s.Trials)
		s.MeanModelCalls /= float64(s.Trials)
	}
	if s.Completed < s.Trials {
		s.Warnings = append(s.Warnings, "incomplete trials remain in denominators")
	}
	if len(durations) > 0 {
		sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
		for _, d := range durations {
			s.MeanDuration += d
		}
		s.MeanDuration /= time.Duration(len(durations))
		s.MedianDuration = durations[len(durations)/2]
	}
	for strategy, b := range s.ByStrategy {
		if b.Trials > 0 {
			b.SuccessRate = float64(b.Successes) / float64(b.Trials)
			b.RegressionRate = float64(b.RegressionFree) / float64(b.Trials)
			b.RootCauseAccuracy = float64(b.RootCauseCorrect) / float64(b.Trials)
			b.MeanExperiments /= float64(b.Trials)
			b.MeanModelCalls /= float64(b.Trials)
			if b.Completed > 0 {
				b.MeanDuration /= time.Duration(b.Completed)
			}
			s.ByStrategy[strategy] = b
		}
	}
	return s
}

func ConfidenceInterval(successes, trials int) (float64, float64, bool) {
	if trials < 2 {
		return 0, 0, false
	}
	p := float64(successes) / float64(trials)
	z := 1.96
	denom := 1 + z*z/float64(trials)
	centre := (p + z*z/(2*float64(trials))) / denom
	margin := z * math.Sqrt((p*(1-p)+z*z/(4*float64(trials)))/float64(trials)) / denom
	return math.Max(0, centre-margin), math.Min(1, centre+margin), true
}

func CompareStrategies(left, right domain.EvaluationStrategy, trials []domain.EvaluationTrial) domain.StrategyComparison {
	comparison := domain.StrategyComparison{Left: left, Right: right}
	leftByCase, rightByCase := map[string]domain.EvaluationTrial{}, map[string]domain.EvaluationTrial{}
	for _, trial := range trials {
		if trial.Strategy == left {
			leftByCase[trial.CaseID] = trial
		}
		if trial.Strategy == right {
			rightByCase[trial.CaseID] = trial
		}
	}
	leftSuccess, rightSuccess := 0, 0
	for caseID, trial := range leftByCase {
		if trial.Outcome == domain.EvaluationSuccess {
			leftSuccess++
		}
		if other, ok := rightByCase[caseID]; ok {
			comparison.PairedTrials++
			_ = other
		}
	}
	for caseID, trial := range rightByCase {
		if trial.Outcome == domain.EvaluationSuccess {
			rightSuccess++
		}
		if _, ok := leftByCase[caseID]; !ok {
			comparison.Warnings = append(comparison.Warnings, "strategies were not run on identical cases")
		}
	}
	if len(leftByCase) > 0 {
		comparison.LeftSuccessRate = float64(leftSuccess) / float64(len(leftByCase))
	}
	if len(rightByCase) > 0 {
		comparison.RightSuccessRate = float64(rightSuccess) / float64(len(rightByCase))
	}
	comparison.AbsoluteDifference = comparison.RightSuccessRate - comparison.LeftSuccessRate
	if comparison.LeftSuccessRate != 0 {
		comparison.RelativeDifference = comparison.AbsoluteDifference / comparison.LeftSuccessRate
	}
	if comparison.PairedTrials < 2 {
		comparison.Warnings = append(comparison.Warnings, "paired sample is too small for a meaningful significance claim")
	}
	return comparison
}

func ReportJSON(summary domain.EvaluationSummary) ([]byte, error) {
	return json.MarshalIndent(summary, "", "  ")
}

func ReportText(summary domain.EvaluationSummary) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Evaluation %s\nSuite %s@%s\nTrials: %d completed: %d\nSuccess: %.1f%% regression-free: %.1f%% root-cause accuracy: %.1f%%\n", summary.EvaluationID, summary.SuiteID, summary.SuiteVersion, summary.Trials, summary.Completed, summary.SuccessRate*100, summary.RegressionRate*100, summary.RootCauseAccuracy*100)
	for strategy, s := range summary.ByStrategy {
		fmt.Fprintf(&b, "%s: %d trials, %.1f%% success, mean duration %s\n", strategy, s.Trials, s.SuccessRate*100, s.MeanDuration)
	}
	for _, warning := range summary.Warnings {
		fmt.Fprintf(&b, "WARNING: %s\n", warning)
	}
	return b.String()
}
