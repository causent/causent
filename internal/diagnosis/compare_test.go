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
	timeout := Baseline{TimedOut: 1, Attempts: 1}
	if got := compareVerdict(basePass, timeout); got != ClassInconclusive {
		t.Fatalf("timeout verdict=%s, want %s", got, ClassInconclusive)
	}
	passTimeout := Baseline{Passes: 1, TimedOut: 1, Attempts: 2}
	if got := compareVerdict(basePass, passTimeout); got != ClassInconclusive {
		t.Fatalf("pass/timeout verdict=%s, want %s", got, ClassInconclusive)
	}
	headUnexecuted := Baseline{Results: []Attempt{{Executed: false}}, Attempts: 1}
	if got := compareVerdict(basePass, headUnexecuted); got != ClassInconclusive {
		t.Fatalf("head unexecuted verdict=%s, want %s", got, ClassInconclusive)
	}
	baseUnexecuted := Baseline{Results: []Attempt{{Executed: false}}, Attempts: 1}
	if got := compareVerdict(baseUnexecuted, headFail); got != ClassInconclusive {
		t.Fatalf("base unexecuted verdict=%s, want %s", got, ClassInconclusive)
	}
	baseTimeout := Baseline{Results: []Attempt{{Executed: true, TimedOut: true}}, TimedOut: 1, Attempts: 1}
	if got := compareVerdict(baseTimeout, headFail); got != ClassInconclusive {
		t.Fatalf("base timeout verdict=%s, want %s", got, ClassInconclusive)
	}
}
