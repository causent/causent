package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Yashbhu/Hades/internal/config"
	"github.com/Yashbhu/Hades/internal/domain"
	"github.com/Yashbhu/Hades/internal/engine"
	"github.com/Yashbhu/Hades/internal/evaluation"
	"github.com/Yashbhu/Hades/internal/execution"
	"github.com/Yashbhu/Hades/internal/persistence"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "init":
		runInit(os.Args[2:])
	case "investigate":
		runInvestigate(os.Args[2:])
	case "status":
		runStatus(os.Args[2:])
	case "report":
		runReport(os.Args[2:])
	case "experiments":
		runExperiments(os.Args[2:])
	case "experiment":
		runExperimentCommand(os.Args[2:])
	case "export-patch":
		runExportPatch(os.Args[2:])
	case "patches":
		runPatches(os.Args[2:])
	case "evaluation":
		runEvaluationCommand(os.Args[2:])
	case "cancel":
		runCancel(os.Args[2:])
	case "replay":
		runReplay(os.Args[2:])
	case "recover":
		runRecover(os.Args[2:])
	case "config", "validate":
		runConfigValidate(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func runPatches(args []string) {
	fs := flag.NewFlagSet("patches", flag.ExitOnError)
	db := fs.String("db", dbPath(), "sqlite db path")
	investigation := fs.String("investigation", "", "investigation ID")
	show := fs.String("show", "", "patch ID")
	compare := fs.Bool("compare", false, "compare candidates")
	cancel := fs.String("cancel", "", "cancel patch verification")
	fs.Parse(args)
	store, err := persistence.Open(*db)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	defer store.Close()
	investigator := &engine.Investigator{Store: store}
	if *cancel != "" {
		if err := investigator.CancelPatch(domain.ID(*cancel)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		fmt.Printf("patch verification cancelled: %s\n", *cancel)
		return
	}
	if *show != "" {
		p, err := store.GetPatch(domain.ID(*show))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		fmt.Printf("patch: %s\nstatus: %s\nvalidation: %s\napplication: %s\nverification: %s\ndigest: %s\nbase_revision: %s\nexplanation: %s\n\n%s\n",
			p.ID, p.Status, p.ValidationStatus, p.ApplicationStatus, p.VerificationStatus, p.Digest, p.BaseRevision, p.Explanation, p.Diff)
		if report, err := store.GetVerificationReport(p.ID); err == nil {
			fmt.Printf("\noriginal_resolved: %t\nregressions_passed: %t\n", report.OriginalResolved, report.RegressionsPassed)
		}
		return
	}
	if *investigation == "" {
		fmt.Fprintln(os.Stderr, "--investigation or --show is required")
		return
	}
	if *compare {
		comparison, err := investigator.ComparePatches(domain.ID(*investigation))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		for _, id := range comparison.Ranked {
			fmt.Printf("%s: %s\n", id, strings.Join(comparison.Reasons[id], "; "))
		}
		return
	}
	patches, err := store.ListPatches(domain.ID(*investigation))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	for _, p := range patches {
		fmt.Printf("%s %s verification=%s digest=%s\n", p.ID, p.Status, p.VerificationStatus, p.Digest)
	}
}

func runInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	db := fs.String("db", dbPath(), "sqlite db path")
	fs.Parse(args)
	if err := os.MkdirAll(filepath.Dir(*db), 0700); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_, err := persistence.Open(*db)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("Hades investigation database initialized.")
}

func runRecover(args []string) {
	fs := flag.NewFlagSet("recover", flag.ExitOnError)
	db := fs.String("db", dbPath(), "sqlite db path")
	fs.Parse(args)
	if err := os.MkdirAll(filepath.Dir(*db), 0700); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	store, err := persistence.Open(*db)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer store.Close()

	investigator := &engine.Investigator{Store: store}
	report, err := investigator.Recover(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("incomplete investigations found: %d\nrecovered: %d\n", report.Found, len(report.Recovered))
	for _, r := range report.Recovered {
		fmt.Printf("  %s: %s -> %s (interrupted experiments: %d)\n", r.InvestigationID, r.PreviousStatus, r.NextStatus, r.InterruptedRun)
		fmt.Printf("    %s\n", r.Note)
	}
}

func runConfigValidate(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	path := fs.String("config", "", "JSON configuration file")
	jsonOutput := fs.Bool("json", false, "machine-readable JSON")
	fs.Parse(args)
	cfg, err := config.Load(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration invalid: "+err.Error())
		os.Exit(2)
	}
	if *jsonOutput {
		writeJSON(cfg)
		return
	}
	fmt.Println("Configuration valid.")
	fmt.Printf("  db path: %s\n  artifacts: %s\n  timeout: %s\n  budget: %d steps\n  max output: %d bytes\n", cfg.DatabasePath, cfg.ArtifactPath, cfg.Timeout, cfg.Budget, cfg.MaxOutput)
}

func usage() {
	fmt.Println("usage: debug <investigate|status|report|experiments|experiment|patches|evaluation|export-patch> [flags]")
}

func runEvaluationCommand(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: debug evaluation <suites|cases|run|show> [flags]")
		return
	}
	switch args[0] {
	case "suites":
		fs := flag.NewFlagSet("evaluation suites", flag.ExitOnError)
		db := fs.String("db", dbPath(), "sqlite db path")
		fs.Parse(args[1:])
		store, err := persistence.Open(*db)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		defer store.Close()
		suites, err := store.ListBenchmarkSuites()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		for _, suite := range suites {
			fmt.Printf("%s@%s: %s (%d cases)\n", suite.ID, suite.Version, suite.Description, len(suite.Cases))
		}
	case "cases":
		fs := flag.NewFlagSet("evaluation cases", flag.ExitOnError)
		db := fs.String("db", dbPath(), "sqlite db path")
		fs.Parse(args[1:])
		store, err := persistence.Open(*db)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		defer store.Close()
		suites, err := store.ListBenchmarkSuites()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		for _, suite := range suites {
			for _, c := range suite.Cases {
				fmt.Printf("%s: %s [%s/%s]\n", c.ID, c.Description, c.Category, c.Difficulty)
			}
		}
	case "run":
		fs := flag.NewFlagSet("evaluation run", flag.ExitOnError)
		corpus := fs.String("corpus", "", "benchmark suite JSON")
		db := fs.String("db", dbPath(), "sqlite db path")
		repo := fs.String("repo", "", "repository root for the cases")
		strategy := fs.String("strategy", "direct_repair,evidence_guided", "comma-separated strategies")
		timeout := fs.Duration("timeout", 30*time.Second, "trial timeout")
		budget := fs.Int("budget", 20, "trial budget")
		fs.Parse(args[1:])
		if *corpus == "" {
			fmt.Fprintln(os.Stderr, "--corpus is required")
			return
		}
		suite, err := evaluation.LoadSuite(*corpus)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		if *repo != "" {
			for idx := range suite.Cases {
				suite.Cases[idx].RepoPath = filepath.Join(*repo, suite.Cases[idx].Repository)
			}
		}
		store, err := persistence.Open(*db)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		defer store.Close()
		allowedDirs := make(map[string]bool, len(suite.Cases))
		for _, benchmarkCase := range suite.Cases {
			canonical, canonicalErr := filepath.EvalSymlinks(benchmarkCase.RepoPath)
			if canonicalErr != nil {
				fmt.Fprintf(os.Stderr, "benchmark case %s repository is unavailable: %v\n", benchmarkCase.ID, canonicalErr)
				return
			}
			allowedDirs[canonical] = true
		}
		policy := execution.Policy{AllowedCommands: map[string]bool{"python3": true, "python": true, "sh": true}, AllowedDirs: allowedDirs, AllowedDirPrefixes: []string{os.TempDir()}, AllowedEnviron: map[string]bool{}, MaxOutput: 64 * 1024, Timeout: *timeout}
		var strategies []domain.EvaluationStrategy
		for _, raw := range strings.Split(*strategy, ",") {
			strategies = append(strategies, domain.EvaluationStrategy(strings.TrimSpace(raw)))
		}
		provider := engine.ProviderFromEnvironment()
		providerName := os.Getenv("HADES_MODEL_PROVIDER")
		modelName := os.Getenv("HADES_MODEL")
		endpoint := os.Getenv("HADES_GATEWAY_ENDPOINT")
		if modelName == "" {
			modelName = os.Getenv("HADES_OLLAMA_MODEL")
		}
		if endpoint == "" {
			endpoint = os.Getenv("HADES_OLLAMA_ENDPOINT")
		}
		modelMetadata := domain.ModelMetadata{Provider: providerName, Model: modelName, Endpoint: endpoint}
		summary, err := evaluation.RunSuite(context.Background(), evaluation.Config{Suite: suite, Strategies: strategies, Budget: *budget, Timeout: *timeout, Model: modelMetadata, Store: store, Provider: provider, Executor: execution.NewLocalExecutor(policy, execution.NewArtifactFactory(filepath.Join(filepath.Dir(*db), "artifacts")))})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		fmt.Print(evaluation.ReportText(summary))
	case "show":
		fs := flag.NewFlagSet("evaluation show", flag.ExitOnError)
		db := fs.String("db", dbPath(), "sqlite db path")
		id := fs.String("id", "", "evaluation ID")
		jsonOutput := fs.Bool("json", false, "machine-readable JSON")
		fs.Parse(args[1:])
		store, err := persistence.Open(*db)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		defer store.Close()
		summary, err := store.GetEvaluationSummary(domain.ID(*id))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		if *jsonOutput {
			data, err := evaluation.ReportJSON(summary)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return
			}
			fmt.Println(string(data))
		} else {
			fmt.Print(evaluation.ReportText(summary))
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown evaluation action")
	}
}

func joinIDs(ids []domain.ID) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = string(id)
	}
	return strings.Join(parts, ", ")
}

func dbPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".hades", "investigations.db")
}

func writeJSON(value interface{}) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		fmt.Fprintln(os.Stderr, "write JSON: "+err.Error())
		os.Exit(1)
	}
}

func runInvestigate(args []string) {
	fs := flag.NewFlagSet("investigate", flag.ExitOnError)
	repo := fs.String("repo", "", "repository path")
	command := fs.String("command", "", "command to run")
	timeout := fs.Duration("timeout", 30*time.Second, "timeout")
	db := fs.String("db", dbPath(), "sqlite db path")
	budget := fs.Int("budget", 20, "maximum investigation steps")
	jsonOutput := fs.Bool("json", false, "machine-readable JSON")
	fs.Parse(args)

	if *repo == "" || *command == "" {
		fmt.Fprintln(os.Stderr, "repo and command are required")
		os.Exit(2)
	}
	cmd := splitCommand(*command)

	if err := os.MkdirAll(filepath.Dir(*db), 0700); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	store, err := persistence.Open(*db)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer store.Close()

	policy := execution.Policy{
		AllowedCommands: map[string]bool{},
		AllowedDirs:     map[string]bool{*repo: true},
		AllowedEnviron:  map[string]bool{},
		MaxOutput:       64 * 1024,
		Timeout:         *timeout,
	}
	for _, part := range cmd {
		policy.AllowedCommands[part] = true
		break
	}
	investigator := &engine.Investigator{
		Store:    store,
		Executor: execution.NewLocalExecutor(policy, execution.NewArtifactFactory(filepath.Join(filepath.Dir(*db), "artifacts"))),
	}
	inv, result, err := investigator.Investigate(
		context.Background(), *repo, cmd, *timeout, *budget,
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *jsonOutput {
		writeJSON(map[string]interface{}{"investigation": inv, "result": result})
		return
	}
	fmt.Printf("investigation: %s\nstatus: %s\nreproducible: %t\nreason: %s\nexit_code: %d\n",
		inv.ID, inv.Status, result.Reproduction.Reproducible, result.Reproduction.Reason, result.Reproduction.Result.ExitCode)
	fmt.Printf("evidence_count: %d\nhypothesis_count: %d\nexperiment_count: %d\n",
		result.EvidenceCount, result.HypothesisCount, result.ExperimentCount)
	if result.Patch != nil {
		fmt.Printf("patch_status: %s\n", result.Patch.Status)
	}
	fmt.Printf("\n%s\n", result.FinalReport)
}

func runStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	db := fs.String("db", dbPath(), "sqlite db path")
	jsonOutput := fs.Bool("json", false, "machine-readable JSON")
	fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "investigation id required")
		os.Exit(2)
	}
	if err := os.MkdirAll(filepath.Dir(*db), 0700); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	store, err := persistence.Open(*db)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer store.Close()
	inv, err := store.GetInvestigation(domain.ID(fs.Arg(0)))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	events, _ := store.ListEvents(inv.ID)
	evidence, _ := store.ListEvidence(inv.ID)
	hypotheses, _ := store.ListHypotheses(inv.ID)
	experiments, _ := store.ListExperiments(inv.ID)
	if *jsonOutput {
		writeJSON(map[string]interface{}{"investigation": inv, "events": events, "evidence": evidence, "hypotheses": hypotheses, "experiments": experiments})
		return
	}
	fmt.Printf("id: %s\nstatus: %s\nrepo: %s\ncommand: %s\n", inv.ID, inv.Status, inv.RepoPath, strings.Join(inv.Command, " "))
	fmt.Printf("budget: %d/%d steps\n", inv.BudgetUsed, inv.BudgetSteps)
	fmt.Printf("evidence: %d items\n", len(evidence))
	fmt.Printf("hypotheses: %d\n", len(hypotheses))
	fmt.Printf("experiments: %d\n", len(experiments))
	fmt.Printf("events: %d\n", len(events))
	for _, ev := range events {
		fmt.Printf("  %s: %s -> %s (%s)\n", ev.Timestamp.Format(time.RFC3339), ev.PreviousStatus, ev.NextStatus, ev.Trigger)
	}
}

func runReport(args []string) {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	db := fs.String("db", dbPath(), "sqlite db path")
	jsonOutput := fs.Bool("json", false, "machine-readable JSON")
	fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "investigation id required")
		os.Exit(1)
	}
	if err := os.MkdirAll(filepath.Dir(*db), 0700); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	store, err := persistence.Open(*db)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer store.Close()
	inv, err := store.GetInvestigation(domain.ID(fs.Arg(0)))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("investigation: %s\nstatus: %s\nrepo: %s\ncommand: %s\n",
		inv.ID, inv.Status, inv.RepoPath, strings.Join(inv.Command, " "))
	fmt.Printf("budget: %d/%d steps\n", inv.BudgetUsed, inv.BudgetSteps)

	evidence, _ := store.ListEvidence(inv.ID)
	hypotheses, _ := store.ListHypotheses(inv.ID)
	experiments, _ := store.ListExperiments(inv.ID)
	patches, _ := store.ListPatches(inv.ID)
	if *jsonOutput {
		writeJSON(map[string]interface{}{"investigation": inv, "evidence": evidence, "hypotheses": hypotheses, "experiments": experiments, "patches": patches})
		return
	}

	fmt.Printf("\nevidence (%d):\n", len(evidence))
	for _, e := range evidence {
		fmt.Printf("  [%s] %s: %s\n", e.Type, e.Source, truncate(e.Payload, 200))
	}
	fmt.Printf("\nhypotheses (%d):\n", len(hypotheses))
	for _, h := range hypotheses {
		fmt.Printf("  [%s] %s (confidence: %.2f)\n", h.Status, h.Statement, h.Confidence)
	}
	fmt.Printf("\nexperiments (%d):\n", len(experiments))
	for _, ex := range experiments {
		fmt.Printf("  [%s] %s: %s\n", ex.Status, ex.Type, ex.Outcome)
	}
	fmt.Printf("\npatches (%d):\n", len(patches))
	for _, p := range patches {
		fmt.Printf("  [%s] %s\n", p.Status, p.ID)
	}
}

func runExperiments(args []string) {
	fs := flag.NewFlagSet("experiments", flag.ExitOnError)
	db := fs.String("db", dbPath(), "sqlite db path")
	fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "investigation id required")
		os.Exit(2)
	}
	if err := os.MkdirAll(filepath.Dir(*db), 0700); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	store, err := persistence.Open(*db)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer store.Close()
	inv, err := store.GetInvestigation(domain.ID(fs.Arg(0)))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	experiments, err := store.ListExperiments(inv.ID)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("investigation: %s\n", inv.ID)
	fmt.Printf("experiments: %d\n\n", len(experiments))
	for _, ex := range experiments {
		fmt.Printf("  ID: %s\n", ex.ID)
		fmt.Printf("  State: %s\n", ex.State)
		fmt.Printf("  Type: %s\n", ex.Type)
		fmt.Printf("  Purpose: %s\n", ex.Purpose)
		fmt.Printf("  Hypotheses: %s\n", joinIDs(ex.HypothesesIDs))
		fmt.Printf("  Command: %s\n", strings.Join(ex.Command, " "))
		fmt.Printf("  Status: %s\n", ex.Status)
		fmt.Printf("  Outcome: %s\n", ex.Outcome)
		if ex.Result != nil {
			fmt.Printf("  Exit code: %d\n", ex.Result.ExitCode)
			fmt.Printf("  Duration: %v\n", ex.Result.Duration)
		}
		if ex.Error != "" {
			fmt.Printf("  Error: %s\n", ex.Error)
		}
		fmt.Printf("\n")
	}
}

func runExperimentCommand(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: debug experiment <show|approve|run|cancel> <experiment-id> [--db path]")
		os.Exit(2)
	}
	action, id := args[0], domain.ID(args[1])
	fs := flag.NewFlagSet("experiment", flag.ExitOnError)
	db := fs.String("db", dbPath(), "sqlite db path")
	fs.Parse(args[2:])
	if err := os.MkdirAll(filepath.Dir(*db), 0700); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	store, err := persistence.Open(*db)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer store.Close()
	ex, err := store.GetExperiment(id)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if action == "show" {
		fmt.Printf("id: %s\ninvestigation: %s\nstate: %s\nstatus: %s\npurpose: %s\ndescription: %s\ncommand: %s\nreason: %s\nobservations: %s\nevaluation: %s\nevidence: %s\n",
			ex.ID, ex.InvestigationID, ex.State, ex.Status, ex.Purpose, ex.Description,
			strings.Join(ex.Command, " "), ex.SelectionReason, ex.Observations, ex.Evaluation, joinIDs(ex.EvidenceProduced))
		fmt.Println("predictions:")
		for id, prediction := range ex.Predictions {
			fmt.Printf("  %s: %s\n", id, prediction)
		}
		return
	}
	inv, err := store.GetInvestigation(ex.InvestigationID)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	investigator := &engine.Investigator{
		Store: store,
		Executor: execution.NewLocalExecutor(execution.Policy{
			AllowedCommands: map[string]bool{inv.Command[0]: true, "python3": true},
			AllowedDirs:     map[string]bool{inv.RepoPath: true},
			AllowedEnviron:  map[string]bool{},
			MaxOutput:       64 * 1024, Timeout: 30 * time.Second,
		}, execution.NewArtifactFactory(filepath.Join(filepath.Dir(*db), "artifacts"))),
	}
	switch action {
	case "approve":
		err = investigator.ApproveExperiment(context.Background(), id)
	case "run":
		_, err = investigator.RunApprovedExperiment(context.Background(), id)
	case "cancel":
		err = investigator.CancelExperiment(id)
	default:
		fmt.Fprintln(os.Stderr, "unknown experiment action")
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("experiment %s: %s\n", id, action)
}

func runExportPatch(args []string) {
	fs := flag.NewFlagSet("export-patch", flag.ExitOnError)
	db := fs.String("db", dbPath(), "sqlite db path")
	output := fs.String("output", "", "output file path")
	fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "investigation id required")
		os.Exit(2)
	}
	if *output == "" {
		fmt.Fprintln(os.Stderr, "--output required")
		os.Exit(2)
	}
	if err := os.MkdirAll(filepath.Dir(*db), 0700); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	store, err := persistence.Open(*db)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer store.Close()
	inv, err := store.GetInvestigation(domain.ID(fs.Arg(0)))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	patches, err := store.ListPatches(inv.ID)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if len(patches) == 0 {
		fmt.Fprintln(os.Stderr, "no patches found for investigation")
		os.Exit(1)
	}
	patch := patches[len(patches)-1]
	if err := os.WriteFile(*output, []byte(patch.Diff), 0644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("patch exported to %s\n", *output)
	fmt.Printf("status: %s\n", patch.Status)
}

func runCancel(args []string) {
	fs := flag.NewFlagSet("cancel", flag.ExitOnError)
	db := fs.String("db", dbPath(), "sqlite db path")
	fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "investigation id required")
		os.Exit(2)
	}
	if err := os.MkdirAll(filepath.Dir(*db), 0700); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	store, err := persistence.Open(*db)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer store.Close()
	inv, err := store.GetInvestigation(domain.ID(fs.Arg(0)))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if domain.IsTerminal(inv.Status) {
		fmt.Fprintf(os.Stderr, "investigation %s is already in terminal state %s\n", inv.ID, inv.Status)
		os.Exit(1)
	}
	prevStatus := inv.Status
	inv.Status = domain.StatusCancelled
	inv.UpdatedAt = time.Now().UTC()
	if err := store.SaveInvestigation(inv); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	store.SaveEvent(domain.InvestigationEvent{
		ID:              persistence.NewID(),
		InvestigationID: inv.ID,
		PreviousStatus:  prevStatus,
		NextStatus:      domain.StatusCancelled,
		Timestamp:       time.Now().UTC(),
		Trigger:         "cancelled_by_user",
	})
	fmt.Printf("investigation %s cancelled\n", inv.ID)
}

func runReplay(args []string) {
	fs := flag.NewFlagSet("replay", flag.ExitOnError)
	db := fs.String("db", dbPath(), "sqlite db path")
	fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "investigation id required")
		os.Exit(2)
	}
	if err := os.MkdirAll(filepath.Dir(*db), 0700); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	store, err := persistence.Open(*db)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer store.Close()
	inv, err := store.GetInvestigation(domain.ID(fs.Arg(0)))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	events, err := store.ListEvents(inv.ID)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("investigation: %s\n", inv.ID)
	fmt.Printf("replaying %d events:\n\n", len(events))
	for _, ev := range events {
		fmt.Printf("  %s  %s -> %s  [%s]", ev.Timestamp.Format(time.RFC3339), ev.PreviousStatus, ev.NextStatus, ev.Trigger)
		if ev.ExperimentID != "" {
			fmt.Printf("  experiment=%s", ev.ExperimentID)
		}
		if ev.EvidenceID != "" {
			fmt.Printf("  evidence=%s", ev.EvidenceID)
		}
		if ev.Error != "" {
			fmt.Printf("  error=%s", ev.Error)
		}
		fmt.Printf("\n")
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

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
