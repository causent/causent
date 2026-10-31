// Command cypher is the diagnosis-first entry point.
//
//	cypher diagnose --repo <path> --command "<failing command>"
//	cypher replay ./bundle
//	cypher repair --repo <path> --command "<command>"   # explicit opt-in
//
// diagnose is the default workflow: reproduce, classify, localize, and produce
// a replayable bundle. It never edits the repository and never claims a fix.
// repair keeps the older patch-generating workflow and must be requested
// explicitly.
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

	"github.com/Yashbhu/Hades/internal/diagnosis"
	"github.com/Yashbhu/Hades/internal/engine"
	"github.com/Yashbhu/Hades/internal/execution"
	"github.com/Yashbhu/Hades/internal/persistence"
)

const version = "0.2.0-diagnosis"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "diagnose", "diagnosis":
		runDiagnose(os.Args[2:])
	case "replay":
		runReplay(os.Args[2:])
	case "repair":
		runRepair(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("cypher " + version)
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Print(`usage: cypher <command> [flags]

commands:
  diagnose   reproduce, classify, localize, and record a replayable bundle (default)
  replay     re-run the checks recorded in a diagnosis bundle
  repair     run the legacy patch-generating workflow (explicit opt-in)
  version    print the version

run "cypher <command> -h" for command flags.
`)
}

func runDiagnose(args []string) {
	fs := flag.NewFlagSet("diagnose", flag.ExitOnError)
	repo := fs.String("repo", ".", "repository path")
	command := fs.String("command", "", "failing command to reproduce")
	attempts := fs.Int("attempts", diagnosis.DefaultAttempts, "reproduction attempts")
	timeout := fs.Duration("timeout", diagnosis.DefaultTimeout, "timeout per attempt")
	db := fs.String("db", envOr("HADES_DB", dbPath()), "sqlite db path for persisted events")
	bundle := fs.String("bundle", "", "bundle output directory (default <repo>/.cypher/bundles/<timestamp>)")
	good := fs.String("good", "", "known-good revision; enables git bisect")
	maxCommits := fs.Int("max-commits", diagnosis.DefaultMaxCommits, "maximum commits to search when --good is not set")
	var probes stringList
	fs.Var(&probes, "probe", "optional diagnostic command; repeatable; never a fix")
	jsonOutput := fs.Bool("json", false, "machine-readable JSON")
	fs.Parse(args)

	if *command == "" {
		fmt.Fprintln(os.Stderr, "cypher diagnose: --command is required")
		os.Exit(2)
	}
	cmd := splitCommand(*command)
	if len(cmd) == 0 {
		fmt.Fprintln(os.Stderr, "cypher diagnose: --command is empty")
		os.Exit(2)
	}
	if *repo == "" {
		fmt.Fprintln(os.Stderr, "cypher diagnose: --repo is required")
		os.Exit(2)
	}
	repoPath, err := filepath.Abs(*repo)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	bundleDir := *bundle
	if bundleDir == "" {
		bundleDir = filepath.Join(repoPath, ".cypher", "bundles", time.Now().UTC().Format("20060102T150405Z"))
	}

	store, err := openStore(*db)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer store.Close()

	cfg := diagnosis.Config{
		RepoPath:   repoPath,
		Command:    cmd,
		Attempts:   *attempts,
		Timeout:    *timeout,
		Executor:   localExecutor(repoPath, *timeout, cmd, probes),
		Store:      store,
		BundleDir:  bundleDir,
		GoodRef:    *good,
		MaxCommits: *maxCommits,
	}
	for _, probe := range probes {
		cfg.Probes = append(cfg.Probes, splitCommand(probe))
	}

	report, err := diagnosis.Run(context.Background(), cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "diagnosis failed: "+err.Error())
		os.Exit(1)
	}

	if *jsonOutput {
		writeJSON(report)
	} else {
		fmt.Print(diagnosisText(report))
	}
	if !report.Refused && report.BundlePath != "" {
		fmt.Printf("\nbundle: %s\nreplay: %s\n", report.BundlePath, report.ReplayCommand)
	}
}

func runReplay(args []string) {
	fs := flag.NewFlagSet("replay", flag.ExitOnError)
	repo := fs.String("repo", "", "override the recorded repository path")
	timeout := fs.Duration("timeout", diagnosis.DefaultTimeout, "timeout per attempt")
	jsonOutput := fs.Bool("json", false, "machine-readable JSON")
	fs.Parse(args)

	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: cypher replay <bundle-dir>")
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

	result, err := diagnosis.Replay(context.Background(), diagnosis.ReplayConfig{
		BundleDir: bundleDir,
		RepoPath:  repoPath,
		Executor:  localExecutor(repoPath, *timeout, command, nil),
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
	db := fs.String("db", envOr("HADES_DB", dbPath()), "sqlite db path")
	jsonOutput := fs.Bool("json", false, "machine-readable JSON")
	fs.Parse(args)

	if *command == "" || *repo == "" {
		fmt.Fprintln(os.Stderr, "cypher repair: --repo and --command are required")
		os.Exit(2)
	}
	repoPath, err := filepath.Abs(*repo)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	cmd := splitCommand(*command)

	store, err := openStore(*db)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer store.Close()

	investigator := &engine.Investigator{
		Store:               store,
		Executor:            localExecutor(repoPath, *timeout, cmd, nil),
		Provider:            engine.ProviderFromEnvironment(),
		DisallowTestChanges: true,
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

	b.WriteString("\nevidence (observations):\n")
	for _, item := range report.Evidence {
		detail := strings.SplitN(item.Detail, "\n", 2)[0]
		fmt.Fprintf(&b, "  %s [%s] %s\n", item.ID, item.Kind, detail)
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
		AllowedEnviron:     map[string]bool{},
		MaxOutput:          64 << 10,
		Timeout:            timeout,
	}
	return execution.NewLocalExecutor(policy, execution.NewArtifactFactory(filepath.Join(filepath.Dir(dbPath()), "artifacts")))
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
	return filepath.Join(home, ".hades", "investigations.db")
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
