package diagnosis

import (
	"fmt"
	"strings"
)

// ValidateContract checks that every claim is explicitly grounded in collected
// evidence. It is intentionally separate from classification so callers can
// validate persisted or imported reports too.
func ValidateContract(report Report) error {
	known := map[string]bool{}
	for _, e := range report.Evidence {
		if e.ID == "" || known[e.ID] {
			return fmt.Errorf("invalid or duplicate evidence ID %q", e.ID)
		}
		known[e.ID] = true
	}
	for _, c := range report.Claims {
		if strings.TrimSpace(c.Statement) == "" {
			return fmt.Errorf("claim %q has empty statement", c.ID)
		}
		if c.Confidence < 0 || c.Confidence > 1 {
			return fmt.Errorf("claim %q confidence outside [0,1]", c.ID)
		}
		for _, id := range append(append([]string{}, c.Supporting...), c.Contradicting...) {
			if !known[id] {
				return fmt.Errorf("claim %q references unknown evidence %q", c.ID, id)
			}
		}
	}
	return nil
}

// Signals are matched against failing output. They are observations about text,
// not proof of cause, so the matched strings are recorded as evidence.
var infrastructureSignals = []string{
	"connection refused",
	"no such host",
	"network is unreachable",
	"temporary failure in name resolution",
	"permission denied",
	"operation not permitted",
	"resource temporarily unavailable",
	"no space left on device",
	"cannot allocate memory",
	"address already in use",
	"cannot connect to the docker daemon",
	"docker: not found",
	"i/o timeout",
	"context deadline exceeded",
}

var dependencySignals = []string{
	"no required module provides package",
	"missing go.sum entry",
	"go.mod requires go >=",
	"toolchain not available",
	"cannot find package",
	"cannot find module",
	"module not found",
	"command not found",
	"npm err! code eresolve",
	"npm err! missing script",
	"failed to select a version",
	"no matching package named",
	"could not find a version that satisfies",
	"requires-python",
	"error: failed to run custom build command",
	"linker `cc` not found",
	"undefined reference to",
}

// Classify assigns the deterministic failure category for a set of attempts.
func Classify(attempts []Attempt) Classification {
	class, _ := classifyWithSignals(attempts)
	return class
}

func classifyWithSignals(attempts []Attempt) (Classification, []string) {
	if len(attempts) == 0 {
		return ClassNotReproduced, nil
	}
	failures, passes, timedOut := 0, 0, 0
	var output strings.Builder
	for _, a := range attempts {
		switch {
		case a.Failed():
			failures++
			output.WriteString(a.Stderr)
			output.WriteString("\n")
		case a.Passed():
			passes++
		}
		if a.TimedOut {
			timedOut++
			output.WriteString(a.Stderr)
			output.WriteString("\n")
		}
	}

	if failures == 0 {
		return ClassNotReproduced, nil
	}
	// Mixed outcomes across identical runs are the definition of a flake.
	if passes > 0 {
		return ClassFlaky, nil
	}

	text := strings.ToLower(output.String())
	// A timeout on every attempt is an environment/limit observation. It can
	// hide a hang introduced by a regression, which is recorded as uncertainty.
	if timedOut == failures {
		return ClassInfrastructure, []string{"all attempts timed out"}
	}

	infra := matchSignals(text, infrastructureSignals)
	deps := matchSignals(text, dependencySignals)
	switch {
	case len(infra) > 0 && len(deps) > len(infra):
		return ClassDependencyDrift, deps
	case len(infra) > 0:
		return ClassInfrastructure, infra
	case len(deps) > 0:
		return ClassDependencyDrift, deps
	default:
		return ClassRealRegression, nil
	}
}

func matchSignals(text string, signals []string) []string {
	var matched []string
	for _, signal := range signals {
		if strings.Contains(text, signal) {
			matched = append(matched, signal)
		}
	}
	return matched
}

// refusalReason reports whether the run must not claim a diagnosis.
func refusalReason(class Classification, baseline Baseline) (string, bool) {
	executed := 0
	for _, a := range baseline.Results {
		if a.Executed {
			executed++
		}
	}
	if executed == 0 {
		return "the command never executed: no attempt produced a process result", true
	}
	if class == ClassNotReproduced {
		return fmt.Sprintf("the command did not fail in %d attempts; there is no observed failure to diagnose", baseline.Attempts), true
	}
	return "", false
}

func attemptEvidence(baseline Baseline) []EvidenceItem {
	items := make([]EvidenceItem, 0, len(baseline.Results))
	for _, a := range baseline.Results {
		detail := fmt.Sprintf("attempt=%d exit_code=%d executed=%t timed_out=%t duration=%s", a.Index+1, a.ExitCode, a.Executed, a.TimedOut, a.Duration)
		if a.Error != "" {
			detail += " error=" + a.Error
		}
		if a.Stderr != "" {
			detail += "\noutput:\n" + a.Stderr
		}
		items = append(items, EvidenceItem{
			ID:     fmt.Sprintf("E-attempt-%d", a.Index+1),
			Kind:   "reproduction_attempt",
			Source: strings.Join(baseline.Command, " "),
			Digest: a.StderrDigest,
			Detail: bound(detail, MaxEvidenceExcerpt),
		})
	}
	return items
}

func classificationEvidence(class Classification, baseline Baseline) EvidenceItem {
	_, signals := classifyWithSignals(baseline.Results)
	detail := fmt.Sprintf("classification=%s failures=%d passes=%d timed_out=%d attempts=%d",
		class, baseline.Failures, baseline.Passes, baseline.TimedOut, baseline.Attempts)
	if len(signals) > 0 {
		detail += "\nmatched_signals=" + strings.Join(signals, ", ")
	}
	return EvidenceItem{
		ID:     "E-classification",
		Kind:   "classification",
		Source: "exit codes and bounded output of the reproduced command",
		Digest: digestString(detail),
		Detail: detail,
	}
}

func buildClaims(class Classification, loc Localization, evidence []EvidenceItem) []Claim {
	var claims []Claim

	attemptIDs := make([]string, 0, len(evidence))
	for _, e := range evidence {
		if e.Kind == "reproduction_attempt" {
			attemptIDs = append(attemptIDs, e.ID)
		}
	}

	statement := map[Classification]string{
		ClassRealRegression:  "The failure reproduces deterministically in the current revision and is most likely a real regression rather than a flake or environment fault.",
		ClassFlaky:           "The same command produced both passing and failing runs, so the failure is flaky rather than deterministic.",
		ClassDependencyDrift: "The failure output matches dependency or toolchain errors, so the cause is most likely a version or toolchain mismatch rather than application logic.",
		ClassInfrastructure:  "The failure output matches environment or infrastructure errors, so the cause is most likely the execution environment rather than application logic.",
	}[class]
	if statement != "" {
		claims = append(claims, Claim{
			ID:         "H-classification",
			Statement:  statement,
			Confidence: confidence(class, loc, nil),
			Supporting: append([]string{"E-classification"}, attemptIDs...),
		})
	}

	if loc.FirstKnownBad != "" || loc.BisectResult != "" {
		bad := loc.FirstKnownBad
		if loc.BisectResult != "" {
			bad = loc.BisectResult
		}
		statement := fmt.Sprintf("The change that introduced the failure is most likely %s", bad)
		support := []string{"E-git-first-bad"}
		if loc.BisectResult != "" {
			statement = fmt.Sprintf("git bisect identified %s as the first bad commit", bad)
			support = append(support, "E-git-bisect")
		}
		if loc.LastKnownGood != "" {
			statement += fmt.Sprintf(", first observed after %s", loc.LastKnownGood)
			support = append(support, "E-git-last-good")
		}
		claims = append(claims, Claim{
			ID:         "H-localization",
			Statement:  statement,
			Confidence: confidence(class, loc, nil),
			Supporting: support,
		})
	}

	if len(loc.LikelyFiles) > 0 {
		claims = append(claims, Claim{
			ID:         "H-affected-files",
			Statement:  "The most likely affected files are " + strings.Join(loc.LikelyFiles, ", "),
			Confidence: 0.5,
			Supporting: []string{"E-git-diff"},
		})
	}

	if len(loc.LikelyFunctions) > 0 {
		claims = append(claims, Claim{
			ID:         "H-stack-frames",
			Statement:  "Failure output references " + strings.Join(loc.LikelyFunctions, ", ") + "; these are heuristic mentions, not confirmed fault sites",
			Confidence: 0.35,
			Supporting: []string{"E-attempt-1"},
		})
	}
	return claims
}

func confidence(class Classification, loc Localization, uncertainty []string) float64 {
	base := map[Classification]float64{
		ClassRealRegression:  0.75,
		ClassFlaky:           0.8,
		ClassDependencyDrift: 0.65,
		ClassInfrastructure:  0.55,
		ClassNotReproduced:   0.0,
	}[class]

	if loc.BisectResult != "" {
		base += 0.1
	}
	if loc.LastKnownGood != "" && loc.FirstKnownBad != "" {
		base += 0.05
	}
	if len(loc.LikelyFiles) > 0 {
		base += 0.05
	}
	penalty := 0.05 * float64(len(uncertainty))
	if penalty > 0.2 {
		penalty = 0.2
	}
	base -= penalty
	if base < 0 {
		base = 0
	}
	if base > 0.95 {
		base = 0.95
	}
	return base
}

func defaultUncertainty(class Classification, loc Localization) []string {
	items := []string{
		"the classification is derived from exit codes and bounded command output, not from inspecting application state",
	}
	switch class {
	case ClassFlaky:
		items = append(items, "flakiness depends on machine load and timing; the observed ratio is not a calibrated probability")
	case ClassInfrastructure:
		items = append(items, "an environment fault can mask an underlying regression, so the cause may be conflated")
	case ClassDependencyDrift:
		items = append(items, "matching dependency error text does not prove the dependency is the only difference between revisions")
	}
	if loc.BisectResult == "" {
		items = append(items, "no verified git bisect result was produced; first-bad is based on a bounded walk from HEAD")
	}
	if loc.LastKnownGood == "" {
		items = append(items, "no known-good commit was found within the search bound, so the introduction point is unknown")
	}
	return items
}
