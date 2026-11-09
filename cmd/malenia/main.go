// Command malenia is the diagnosis-first entry point.
//
//	malenia diagnose --repo <path> --command "<failing command>"
//	malenia replay ./bundle
//	malenia repair --repo <path> --command "<command>"   # explicit opt-in
//
// diagnose is the default workflow: reproduce, classify, localize, and produce
// a replayable bundle. It never edits the repository and never claims a fix.
// repair keeps the older patch-generating workflow and must be requested
// explicitly.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/causent/malenia/internal/agent"
	"github.com/causent/malenia/internal/diagnosis"
	"github.com/causent/malenia/internal/domain"
	"github.com/causent/malenia/internal/engine"
	"github.com/causent/malenia/internal/evalcorpus"
	"github.com/causent/malenia/internal/execution"
	"github.com/causent/malenia/internal/persistence"
)

const defaultVersion = "0.2.0-diagnosis"

// version is overridden at build time with -X main.version=<tag>.
var version = defaultVersion

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "init":
		runInit(os.Args[2:])
	case "diagnose", "diagnosis":
		runDiagnose(os.Args[2:])
	case "analyze":
		runAnalyze(os.Args[2:])
	case "replay":
		runReplay(os.Args[2:])
	case "repair":
		runRepair(os.Args[2:])
	case "eval":
		runEval(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("malenia " + version)
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Print(`usage: malenia <command> [flags]

commands:
  init       detect the repository and generate Malenia integration files
  diagnose   reproduce, classify, localize, and record a replayable bundle (default)
  analyze    analyze an existing deterministic report with the configured model
  replay     re-run the checks recorded in a diagnosis bundle
  repair     run the legacy patch-generating workflow (explicit opt-in)
  eval       manage the frozen evaluation corpus
  version    print the version

run "malenia <command> -h" for command flags.
`)
}

func runEval(args []string) {
	if len(args) == 0 || args[0] != "freeze" {
		fmt.Fprintln(os.Stderr, "usage: malenia eval freeze")
		os.Exit(2)
	}
	repo, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	record, err := evalcorpus.Freeze(repo)
	if err != nil {
		fmt.Fprintln(os.Stderr, "eval freeze: "+err.Error())
		os.Exit(1)
	}
	fmt.Printf("evaluation corpus frozen at manifest commit %s\n", record.ManifestCommit)
}

func runDiagnose(args []string) {
	fs := flag.NewFlagSet("diagnose", flag.ExitOnError)
	repo := fs.String("repo", ".", "repository path")
	command := fs.String("command", "", "failing command to reproduce")
	attempts := fs.Int("attempts", diagnosis.DefaultAttempts, "reproduction attempts")
	timeout := fs.Duration("timeout", diagnosis.DefaultTimeout, "timeout per attempt")
	investigationTimeout := fs.Duration("investigation-timeout", 0, "maximum duration for the complete diagnosis")
	db := fs.String("db", envOr("MALENIA_DB", dbPath()), "sqlite db path for persisted events")
	bundle := fs.String("bundle", "", "bundle output directory (default <repo>/.malenia/bundles/<timestamp>)")
	good := fs.String("good", "", "known-good revision; enables git bisect")
	base := fs.String("base", "", "known base revision; compare its outcome with HEAD")
	maxCommits := fs.Int("max-commits", diagnosis.DefaultMaxCommits, "maximum commits to search when --good is not set")
	maxProbes := fs.Int("max-probes", diagnosis.DefaultMaxLocalizationProbes, "maximum test executions used to locate a revision boundary")
	skipAdaptive := fs.Bool("skip-adaptive", false, "publish the preliminary diagnosis without optional adaptive investigation")
	executorMode := fs.String("executor", envOr("MALENIA_EXECUTOR", "local"), "execution backend: local or docker")
	image := fs.String("image", envOr("MALENIA_EXECUTOR_IMAGE", ""), "Docker image (required with --executor docker)")
	var probes stringList
	fs.Var(&probes, "probe", "optional diagnostic command; repeatable; never a fix")
	jsonOutput := fs.Bool("json", false, "machine-readable JSON")
	useAgent := fs.Bool("agent", false, "ask the configured gateway model to analyze collected evidence")
	ciLog := fs.String("ci-log", "", "bounded original CI log to include as evidence")
	junit := fs.String("junit", "", "JUnit XML test report to include as evidence")
	fs.Parse(args)

	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	if *repo == "" {
		fmt.Fprintln(os.Stderr, "malenia diagnose: --repo is required")
		os.Exit(2)
	}
	repoPath, err := filepath.Abs(*repo)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	repoCfg, err := loadRepoConfig(repoPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config: "+err.Error())
		os.Exit(2)
	}
	if !set["command"] {
		*command = repoCfg.Command
	}
	if !set["base"] {
		*base = repoCfg.Base
	}
	if !set["good"] {
		*good = repoCfg.Good
	}
	if !set["attempts"] && repoCfg.Attempts > 0 {
		*attempts = repoCfg.Attempts
	}
	if !set["timeout"] && repoCfg.Timeout != "" {
		*timeout, err = time.ParseDuration(repoCfg.Timeout)
		if err != nil {
			fmt.Fprintln(os.Stderr, "config: timeout: "+err.Error())
			os.Exit(2)
		}
	}
	if !set["executor"] && os.Getenv("MALENIA_EXECUTOR") == "" && repoCfg.Executor != "" {
		*executorMode = repoCfg.Executor
	}
	if !set["image"] && os.Getenv("MALENIA_EXECUTOR_IMAGE") == "" && repoCfg.Image != "" {
		*image = repoCfg.Image
	}
	if !set["agent"] {
		*useAgent = repoCfg.Agent
	}
	probes = append(probes, repoCfg.Probes...)

	if *command == "" {
		fmt.Fprintln(os.Stderr, "malenia diagnose: --command is required (or set command in .malenia.yml)")
		os.Exit(2)
	}
	cmd := splitCommand(*command)
	if len(cmd) == 0 {
		fmt.Fprintln(os.Stderr, "malenia diagnose: --command is empty")
		os.Exit(2)
	}

	bundleDir := *bundle
	if bundleDir == "" {
		bundleDir = filepath.Join(repoPath, ".malenia", "bundles", time.Now().UTC().Format("20060102T150405Z"))
	}

	store, err := openStore(*db)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer store.Close()

	executor, err := buildExecutor(*executorMode, *image, repoPath, *timeout, cmd, probes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "executor: "+err.Error())
		os.Exit(2)
	}
	cfg := diagnosis.Config{
		RepoPath:              repoPath,
		Command:               cmd,
		Attempts:              *attempts,
		Timeout:               *timeout,
		InvestigationTimeout:  *investigationTimeout,
		Executor:              executor,
		ExecutorName:          strings.ToLower(*executorMode),
		ExecutorImage:         strings.TrimSpace(*image),
		Store:                 store,
		BundleDir:             bundleDir,
		GoodRef:               *good,
		BaseRef:               *base,
		MaxCommits:            *maxCommits,
		MaxLocalizationProbes: *maxProbes,
		SkipAdaptive:          *skipAdaptive,
	}
	if strings.TrimSpace(*ciLog) != "" {
		f, readErr := os.Open(*ciLog)
		if readErr != nil {
			fmt.Fprintln(os.Stderr, "ci log: "+readErr.Error())
			os.Exit(2)
		}
		data, readErr := io.ReadAll(io.LimitReader(f, 256<<10))
		_ = f.Close()
		if readErr != nil {
			fmt.Fprintln(os.Stderr, "ci log: "+readErr.Error())
			os.Exit(2)
		}
		digest := sha256.Sum256(data)
		cfg.ExternalEvidence = []diagnosis.EvidenceItem{{ID: "E-ci-log", Kind: "original_ci_log", Source: *ciLog, Digest: hex.EncodeToString(digest[:]), Detail: string(data)}}
	}
	if strings.TrimSpace(*junit) != "" {
		data, readErr := os.ReadFile(*junit)
		if readErr != nil {
			fmt.Fprintln(os.Stderr, "junit: "+readErr.Error())
			os.Exit(2)
		}
		digest := sha256.Sum256(data)
		cfg.ExternalEvidence = append(cfg.ExternalEvidence, diagnosis.EvidenceItem{ID: "E-junit", Kind: "junit_xml", Source: *junit, Digest: hex.EncodeToString(digest[:]), Detail: string(data)})
	}
	if *useAgent {
		cfg.Agent, err = configuredAgent()
		if err != nil {
			fmt.Fprintln(os.Stderr, "agent configuration: "+err.Error())
			os.Exit(2)
		}
	}
	for _, probe := range probes {
		cfg.Probes = append(cfg.Probes, splitCommand(probe))
	}

	report, err := diagnosis.Run(context.Background(), cfg)
	if err != nil {
		if *jsonOutput {
			// Preserve partial evidence so timeout and cancellation failures can
			// still be consumed by CI and persisted as a useful report.
			writeJSON(report)
		}
		fmt.Fprintln(os.Stderr, "diagnosis failed: "+err.Error())
		if report.Partial || report.Refused {
			return
		}
		os.Exit(1)
	}

	if *jsonOutput {
		writeJSON(report)
	} else {
		fmt.Print(diagnosisText(report))
		if !report.Refused && report.BundlePath != "" {
			fmt.Printf("\nbundle: %s\nreplay: %s\n", report.BundlePath, report.ReplayCommand)
		}
	}
}

func configuredAgent() (*agent.Client, error) {
	endpoint := strings.TrimRight(strings.TrimSpace(os.Getenv("MALENIA_GATEWAY_ENDPOINT")), "/")
	model := strings.TrimSpace(os.Getenv("MALENIA_GATEWAY_MODEL"))
	if endpoint == "" {
		return nil, fmt.Errorf("MALENIA_GATEWAY_ENDPOINT is required when model analysis is enabled")
	}
	if model == "" {
		return nil, fmt.Errorf("MALENIA_GATEWAY_MODEL is required when model analysis is enabled")
	}
	return &agent.Client{Endpoint: endpoint, Model: model}, nil
}

// runAnalyze processes only a deterministic report artifact. It never checks
// out or executes repository code, making it suitable for a trusted workflow
// job that alone receives model credentials.
func runAnalyze(args []string) {
	fs := flag.NewFlagSet("analyze", flag.ExitOnError)
	reportPath := fs.String("report", "", "deterministic diagnosis report JSON")
	outputPath := fs.String("output", "", "output path for the combined report JSON")
	fs.Parse(args)
	if *reportPath == "" || *outputPath == "" {
		fmt.Fprintln(os.Stderr, "usage: malenia analyze --report report.json --output combined-report.json")
		os.Exit(2)
	}
	data, err := os.ReadFile(*reportPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "analyze: read report: "+err.Error())
		os.Exit(1)
	}
	var report diagnosis.Report
	if err := json.Unmarshal(data, &report); err != nil {
		fmt.Fprintln(os.Stderr, "analyze: decode report: "+err.Error())
		os.Exit(1)
	}
	if err := diagnosis.ValidateContract(report); err != nil {
		fmt.Fprintln(os.Stderr, "analyze: invalid deterministic report: "+err.Error())
		os.Exit(1)
	}
	client, err := configuredAgent()
	if err != nil {
		fmt.Fprintln(os.Stderr, "agent configuration: "+err.Error())
		os.Exit(2)
	}
	input := agent.Input{
		Classification: string(report.Classification),
		Command:        report.Command,
		Context: fmt.Sprintf("first_known_bad=%s\nlikely_files=%s\nclaims=%v",
			report.Localization.FirstKnownBad, strings.Join(report.Localization.LikelyFiles, ", "), report.Claims),
	}
	for _, e := range report.Evidence {
		input.Evidence = append(input.Evidence, agent.Evidence{ID: e.ID, Kind: e.Kind, Detail: e.Detail})
	}
	report.AgentStatus = "enabled"
	if result, agentErr := client.Analyze(context.Background(), input); agentErr != nil {
		report.AgentStatus = "failed"
		report.AgentError = agentErr.Error()
	} else {
		report.AgentStatus = "completed"
		report.Agent = &result
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "analyze: encode report: "+err.Error())
		os.Exit(1)
	}
	if err := os.WriteFile(*outputPath, append(encoded, '\n'), 0600); err != nil {
		fmt.Fprintln(os.Stderr, "analyze: write report: "+err.Error())
		os.Exit(1)
	}
}

func runReplay(args []string) {
	fs := flag.NewFlagSet("replay", flag.ExitOnError)
	repo := fs.String("repo", "", "override the recorded repository path")
	timeout := fs.Duration("timeout", diagnosis.DefaultTimeout, "timeout per attempt")
	executorMode := fs.String("executor", envOr("MALENIA_EXECUTOR", "local"), "execution backend: local or docker")
	image := fs.String("image", envOr("MALENIA_EXECUTOR_IMAGE", ""), "Docker image (required with --executor docker)")
	jsonOutput := fs.Bool("json", false, "machine-readable JSON")
	fs.Parse(args)

	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: malenia replay <bundle-dir>")
		os.Exit(2)
	}
	bundleDir := fs.Arg(0)

	// The executor needs a command allowlist, but the command lives in the
	// bundle. Allow only the first token recorded in the manifest.
	command := recordedCommand(bundleDir)
	if len(command) == 0 {
		fmt.Fprintln(os.Stderr, "replay failed: bundle does not record a command")
		os.Exit(1)
	}
	repoPath := *repo
	if repoPath == "" {
		repoPath = recordedRepo(bundleDir)
	}
	if repoPath == "" {
		fmt.Fprintln(os.Stderr, "replay failed: bundle does not record a repository path; pass --repo")
		os.Exit(1)
	}
	if abs, err := filepath.Abs(repoPath); err == nil {
		repoPath = abs
	}

	executor, err := buildExecutor(*executorMode, *image, repoPath, *timeout, command, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "executor: "+err.Error())
		os.Exit(2)
	}
	result, err := diagnosis.Replay(context.Background(), diagnosis.ReplayConfig{
		BundleDir: bundleDir,
		RepoPath:  repoPath,
		Executor:  executor,
		Timeout:   *timeout,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "replay failed: "+err.Error())
		os.Exit(1)
	}

	if *jsonOutput {
		writeJSON(result)
	} else {
		fmt.Print(replayText(result))
	}
	if !result.Matched {
		os.Exit(1)
	}
}

func runRepair(args []string) {
	fs := flag.NewFlagSet("repair", flag.ExitOnError)
	repo := fs.String("repo", ".", "repository path")
	command := fs.String("command", "", "command that reproduces the failure")
	timeout := fs.Duration("timeout", 2*time.Minute, "timeout per command")
	budget := fs.Int("budget", 20, "maximum investigation steps")
	maxAttempts := fs.Int("max-attempts", 0, "maximum isolated patch verification attempts (default 2, max 5)")
	modelProposals := fs.Bool("model-proposals", false, "use the separate model patch-proposal path (opt-in)")
	executorMode := fs.String("executor", envOr("MALENIA_EXECUTOR", "local"), "execution backend: local or docker")
	image := fs.String("image", envOr("MALENIA_EXECUTOR_IMAGE", ""), "Docker image (required with --executor docker)")
	db := fs.String("db", envOr("MALENIA_DB", dbPath()), "sqlite db path")
	jsonOutput := fs.Bool("json", false, "machine-readable JSON")
	fs.Parse(args)

	if *command == "" || *repo == "" {
		fmt.Fprintln(os.Stderr, "malenia repair: --repo and --command are required")
		os.Exit(2)
	}
	repoPath, err := filepath.Abs(*repo)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	repoCfg, err := loadRepoConfig(repoPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config: "+err.Error())
		os.Exit(2)
	}
	if *command == "" {
		*command = repoCfg.Command
	}
	if *maxAttempts == 0 {
		*maxAttempts = repoCfg.Repair.MaxAttempts
	}
	cmd := splitCommand(*command)

	store, err := openStore(*db)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer store.Close()

	executor, err := buildExecutor(*executorMode, *image, repoPath, *timeout, cmd, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "executor: "+err.Error())
		os.Exit(2)
	}
	provider := engine.ProviderFromEnvironment()
	investigator := &engine.Investigator{
		Store:               store,
		Executor:            executor,
		Provider:            provider,
		PatchAttempts:       *maxAttempts,
		DisallowTestChanges: true,
	}
	if *modelProposals {
		proposalProvider, ok := provider.(engine.ProposalProvider)
		if !ok {
			fmt.Fprintln(os.Stderr, "repair: configured provider does not support model proposals")
			os.Exit(2)
		}
		investigator.ProposalProvider = proposalProvider
		investigator.ProposalEnabled = true
	}
	inv, result, err := investigator.Investigate(context.Background(), repoPath, cmd, *timeout, *budget)
	if err != nil {
		fmt.Fprintln(os.Stderr, "repair failed: "+err.Error())
		os.Exit(1)
	}
	if *jsonOutput {
		writeJSON(map[string]any{"investigation": inv, "result": result})
		return
	}
	fmt.Printf("investigation: %s\nstatus: %s\n", inv.ID, inv.Status)
	if result.Reproduction != nil && result.Reproduction.Result != nil {
		fmt.Printf("reproduced: %t\nexit_code: %d\nreason: %s\n",
			result.Reproduction.Reproducible, result.Reproduction.Result.ExitCode, result.Reproduction.Reason)
	}
	if result.Patch != nil {
		fmt.Printf("patch: %s verification: %s\n", result.Patch.Status, result.Patch.VerificationStatus)
		fmt.Println("repair is opt-in and experimental: a patch is reported as successful only after the recorded verification commands pass independently.")
	}
	if result.FinalReport != "" {
		fmt.Printf("\n%s\n", result.FinalReport)
	}
}

func diagnosisText(report diagnosis.Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "investigation: %s\n", report.InvestigationID)
	fmt.Fprintf(&b, "repository: %s\n", report.RepoPath)
	fmt.Fprintf(&b, "command: %s\n", strings.Join(report.Command, " "))
	fmt.Fprintf(&b, "classification: %s\n", report.Classification)
	fmt.Fprintf(&b, "reproduced: %d/%d attempts failed", report.Baseline.Failures, report.Baseline.Attempts)
	if report.Baseline.TimedOut > 0 {
		fmt.Fprintf(&b, " (%d timed out)", report.Baseline.TimedOut)
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "confidence: %.2f\n", report.Confidence)
	if report.Comparison != nil {
		cmp := report.Comparison
		fmt.Fprintf(&b, "comparison: base=%s (%d/%d failed), head=%s (%d/%d failed), verdict=%s\n",
			cmp.BaseCommit, cmp.Base.Failures, cmp.Base.Attempts,
			cmp.HeadCommit, cmp.Head.Failures, cmp.Head.Attempts, cmp.Verdict)
	}

	if report.Refused {
		fmt.Fprintf(&b, "refused: %s\n", report.RefusalReason)
	}

	loc := report.Localization
	fmt.Fprintf(&b, "head: %s\n", loc.HeadCommit)
	fmt.Fprintf(&b, "last_known_good: %s\n", valueOr(loc.LastKnownGood, "unknown"))
	fmt.Fprintf(&b, "first_known_bad: %s\n", valueOr(loc.FirstKnownBad, "unknown"))
	fmt.Fprintf(&b, "bisect: %s", loc.BisectStatus)
	if loc.BisectResult != "" {
		fmt.Fprintf(&b, " (%s)", loc.BisectResult)
	}
	b.WriteString("\n")
	if loc.CommitRange != "" {
		fmt.Fprintf(&b, "changed_range: %s\n", loc.CommitRange)
	}
	if len(loc.LikelyFiles) > 0 {
		fmt.Fprintf(&b, "likely_files:\n  %s\n", strings.Join(loc.LikelyFiles, "\n  "))
	}
	if len(loc.LikelyFunctions) > 0 {
		fmt.Fprintf(&b, "mentioned_functions (heuristic, not confirmed fault sites):\n  %s\n", strings.Join(loc.LikelyFunctions, "\n  "))
	}

	b.WriteString("\nclaims (hypotheses):\n")
	if len(report.Claims) == 0 {
		b.WriteString("  none\n")
	}
	for _, claim := range report.Claims {
		fmt.Fprintf(&b, "  %s (confidence %.2f): %s\n    evidence: %s\n",
			claim.ID, claim.Confidence, claim.Statement, strings.Join(claim.Supporting, ", "))
	}

	if len(report.FailureGroups) > 0 {
		b.WriteString("\nfailure groups:\n")
		for _, group := range report.FailureGroups {
			fmt.Fprintf(&b, "  %s (%s): failures %s\n", group.ID, group.Status, strings.Join(group.FailureIDs, ", "))
		}
	}
	if len(report.FailureEpisodes) > 0 {
		b.WriteString("\nfailed test episodes:\n")
		for _, episode := range report.FailureEpisodes {
			name := episode.TestIdentifier
			if name == "" {
				name = "unknown test"
			}
			fmt.Fprintf(&b, "  %s: %s\n", name, episode.FailureMessage)
		}
	}
	if len(report.Hypotheses) > 0 {
		b.WriteString("\nassessed hypotheses (candidate relevance, not causal probability):\n")
		for _, hypothesis := range report.Hypotheses {
			fmt.Fprintf(&b, "  %s v%d [%s relevance %.2f]: %s\n    supporting evidence: %s\n", hypothesis.ID, hypothesis.Version, hypothesis.Status, hypothesis.Relevance, hypothesis.Statement, strings.Join(idsToStrings(hypothesis.SupportingEvidenceIDs), ", "))
		}
	}
	if len(report.Findings) > 0 {
		b.WriteString("\nvalidated findings:\n")
		for _, finding := range report.Findings {
			fmt.Fprintf(&b, "  [%s] %s\n", finding.Status, finding.Statement)
		}
	}

	b.WriteString("\nevidence (observations):\n")
	for _, item := range report.Evidence {
		detail := strings.SplitN(item.Detail, "\n", 2)[0]
		fmt.Fprintf(&b, "  %s [%s] %s\n", item.ID, item.Kind, detail)
	}
	if report.Agent != nil {
		fmt.Fprintf(&b, "\nagent analysis (%s/%s):\n", report.Agent.Provider, report.Agent.Model)
		for _, h := range report.Agent.Hypotheses {
			fmt.Fprintf(&b, "  (confidence %.2f) %s [%s] evidence: %s\n", h.Confidence, h.Statement, h.Component, strings.Join(h.EvidenceIDs, ", "))
		}
	}

	b.WriteString("\nuncertainty:\n")
	for _, note := range report.Uncertainty {
		fmt.Fprintf(&b, "  - %s\n", note)
	}

	if len(report.Probes) > 0 {
		b.WriteString("\nprobes (diagnostic only, not fixes):\n")
		for _, probe := range report.Probes {
			fmt.Fprintf(&b, "  $ %s -> exit %d\n", probe.Command, probe.ExitCode)
		}
	}
	return b.String()
}

func idsToStrings(ids []domain.ID) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, string(id))
	}
	return out
}

func replayText(result diagnosis.ReplayResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "bundle: %s\n", result.BundlePath)
	fmt.Fprintf(&b, "repository: %s\n", result.RepoPath)
	fmt.Fprintf(&b, "commit: %s\n", result.Commit)
	fmt.Fprintf(&b, "command: %s\n", result.Command)
	fmt.Fprintf(&b, "recorded: classification=%s refused=%t\n", result.RecordedClassification, result.RecordedRefused)
	fmt.Fprintf(&b, "observed: classification=%s refused=%t\n", result.ObservedClassification, result.ObservedRefused)
	for _, attempt := range result.ObservedAttempts {
		fmt.Fprintf(&b, "  attempt %d: exit=%d timed_out=%t\n", attempt.Index+1, attempt.ExitCode, attempt.TimedOut)
	}
	for _, note := range result.Notes {
		fmt.Fprintf(&b, "note: %s\n", note)
	}
	if result.Matched {
		b.WriteString("conclusion: matched\n")
	} else {
		b.WriteString("conclusion: MISMATCH\n")
	}
	return b.String()
}

// localExecutor builds a policy-bounded executor. Command allowlisting is
// derived from the commands the user explicitly asked to run; everything else
// stays behind the execution.Executor interface.
func localExecutor(repoPath string, timeout time.Duration, command []string, probes []string) execution.Executor {
	executor, _ := buildExecutor("local", "", repoPath, timeout, command, probes)
	return executor
}

func buildExecutor(mode, image, repoPath string, timeout time.Duration, command []string, probes []string) (execution.Executor, error) {
	allowed := map[string]bool{}
	if len(command) > 0 {
		allowed[command[0]] = true
	}
	for _, probe := range probes {
		if parts := splitCommand(probe); len(parts) > 0 {
			allowed[parts[0]] = true
		}
	}
	policy := execution.Policy{
		AllowedCommands:    allowed,
		AllowedDirs:        map[string]bool{repoPath: true},
		AllowedDirPrefixes: []string{os.TempDir()},
		// Keep credentials out while preserving the standard toolchain
		// environment needed by Go, Python, Node, and similar commands.
		AllowedEnviron: map[string]bool{
			"HOME": true, "PATH": true, "TMPDIR": true, "TMP": true, "TEMP": true,
			"GOPATH": true, "GOMODCACHE": true, "GOROOT": true, "GOTOOLCHAIN": true,
			"GOENV": true, "LANG": true, "LC_ALL": true,
		},
		MaxOutput: 64 << 10,
		Timeout:   timeout,
	}
	artifacts := execution.NewArtifactFactory(filepath.Join(filepath.Dir(dbPath()), "artifacts"))
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "local":
		return execution.NewLocalExecutor(policy, artifacts), nil
	case "docker":
		image = strings.TrimSpace(image)
		if image == "" {
			return nil, fmt.Errorf("Docker image is required; pass --image or set MALENIA_EXECUTOR_IMAGE")
		}
		collect := execution.CollectPolicy{Image: image, MaxOutput: 64 << 10, Timeout: timeout, MemoryLimitMB: 512, CPULimitPercent: 80, ProcessLimit: 128}
		return execution.NewDockerExecutor(policy, artifacts, collect), nil
	default:
		return nil, fmt.Errorf("unsupported executor %q; choose local or docker", mode)
	}
}

func recordedCommand(bundleDir string) []string {
	manifest, err := diagnosis.ReadManifest(bundleDir)
	if err != nil {
		return nil
	}
	return manifest.Diagnosis.Baseline.Command
}

func recordedRepo(bundleDir string) string {
	manifest, err := diagnosis.ReadManifest(bundleDir)
	if err != nil {
		return ""
	}
	if manifest.Diagnosis.Environment.RepoPath != "" {
		return manifest.Diagnosis.Environment.RepoPath
	}
	return manifest.Diagnosis.RepoPath
}

func openStore(path string) (*persistence.Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	return persistence.Open(path)
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func dbPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".malenia", "investigations.db")
}

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func writeJSON(value any) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		fmt.Fprintln(os.Stderr, "write JSON: "+err.Error())
		os.Exit(1)
	}
}

// stringList collects a repeatable string flag.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

// splitCommand splits a shell-like command string into arguments without
// invoking a shell, so quoting is handled predictably.
func splitCommand(s string) []string {
	var result []string
	var current strings.Builder
	var quote rune
	inToken := false
	for _, r := range s {
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				current.WriteRune(r)
			}
			inToken = true
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			inToken = true
			continue
		}
		if r == ' ' || r == '\t' || r == '\n' {
			if inToken {
				result = append(result, current.String())
				current.Reset()
				inToken = false
			}
			continue
		}
		current.WriteRune(r)
		inToken = true
	}
	if inToken {
		result = append(result, current.String())
	}
	return result
}
