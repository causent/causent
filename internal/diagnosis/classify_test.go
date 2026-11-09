package diagnosis

import "testing"

func TestClassifyTimeoutSemantics(t *testing.T) {
	tests := []struct {
		name     string
		attempts []Attempt
		want     Classification
	}{
		{
			name: "all timeouts are inconclusive",
			attempts: []Attempt{
				{Executed: true, TimedOut: true},
				{Executed: true, TimedOut: true},
			},
			want: ClassInconclusive,
		},
		{
			name: "pass and timeout are inconclusive",
			attempts: []Attempt{
				{Executed: true, ExitCode: 0},
				{Executed: true, TimedOut: true},
			},
			want: ClassInconclusive,
		},
		{
			name: "failure and timeout preserve failure",
			attempts: []Attempt{
				{Executed: true, ExitCode: 1, Stderr: "assertion failed"},
				{Executed: true, TimedOut: true},
			},
			want: ClassRealRegression,
		},
		{
			name: "unexecuted attempt is inconclusive",
			attempts: []Attempt{
				{Executed: false},
			},
			want: ClassInconclusive,
		},
		{
			name: "completed failure and pass are flaky",
			attempts: []Attempt{
				{Executed: true, ExitCode: 1},
				{Executed: true, ExitCode: 0},
			},
			want: ClassFlaky,
		},
		{
			name: "completed pass is not reproduced",
			attempts: []Attempt{
				{Executed: true, ExitCode: 0},
			},
			want: ClassNotReproduced,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := Classify(test.attempts); got != test.want {
				t.Fatalf("classification = %s, want %s", got, test.want)
			}
		})
	}
}
