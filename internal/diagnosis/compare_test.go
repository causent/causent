package diagnosis

import "testing"

func TestCompareVerdict(t *testing.T) {
	basePass := Baseline{Passes: 3, Attempts: 3}
	headFail := Baseline{Failures: 3, Attempts: 3}
	if got := compareVerdict(basePass, headFail); got != ClassRealRegression {
		t.Fatalf("regression verdict=%s", got)
	}
	baseFail := Baseline{Failures: 3, Attempts: 3}
	if got := compareVerdict(baseFail, headFail); got != ClassPreExisting {
		t.Fatalf("pre-existing verdict=%s", got)
	}
	headMixed := Baseline{Failures: 1, Passes: 2, Attempts: 3}
	if got := compareVerdict(basePass, headMixed); got != ClassFlaky {
		t.Fatalf("flaky verdict=%s", got)
	}
	if got := compareVerdict(basePass, basePass); got != ClassNotReproduced {
		t.Fatalf("clean verdict=%s", got)
	}
}
