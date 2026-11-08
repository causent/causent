package localization

import "github.com/causent/causent/internal/domain"

// CandidateContext is the only input signal evaluators may inspect. Keeping
// evaluators separate makes each score dimension auditable and replaceable.
type CandidateContext struct {
	Execution          bool
	Changed            bool
	Expanded           bool
	Behavioural        bool
	Evidence           []domain.ID
	RuntimeEvidence    []domain.ID
	HistoricalEvidence []domain.ID
}

type Signal struct {
	Dimension     string
	Value         float64
	Available     bool
	Evidence      []domain.ID
	Contradicting []domain.ID
}
type SignalEvaluator interface{ Evaluate(CandidateContext) Signal }

type executionEvaluator struct{}

func (executionEvaluator) Evaluate(c CandidateContext) Signal {
	return Signal{Dimension: "execution", Value: 0.95, Available: c.Execution, Evidence: c.Evidence}
}

type changeEvaluator struct{}

func (changeEvaluator) Evaluate(c CandidateContext) Signal {
	return Signal{Dimension: "change", Value: 0.9, Available: c.Changed, Evidence: c.Evidence}
}

type dependencyEvaluator struct{}

func (dependencyEvaluator) Evaluate(c CandidateContext) Signal {
	return Signal{Dimension: "dependency", Value: 0.6, Available: c.Expanded, Evidence: c.Evidence}
}

type behaviouralEvaluator struct{}

func (behaviouralEvaluator) Evaluate(c CandidateContext) Signal {
	return Signal{Dimension: "behavioural", Value: 0.7, Available: c.Behavioural, Evidence: c.Evidence}
}

type historicalEvaluator struct{}

func (historicalEvaluator) Evaluate(c CandidateContext) Signal {
	return Signal{Dimension: "historical", Value: 0.5, Available: len(c.HistoricalEvidence) > 0, Evidence: c.HistoricalEvidence}
}

type runtimeEvaluator struct{}

func (runtimeEvaluator) Evaluate(c CandidateContext) Signal {
	return Signal{Dimension: "runtime", Value: 0.8, Available: len(c.RuntimeEvidence) > 0, Evidence: c.RuntimeEvidence}
}

var defaultEvaluators = []SignalEvaluator{executionEvaluator{}, changeEvaluator{}, dependencyEvaluator{}, behaviouralEvaluator{}, historicalEvaluator{}, runtimeEvaluator{}}

func evaluateSignals(c CandidateContext) domain.ScoreVector {
	v := domain.ScoreVector{ScoringPolicyVersion: PolicyVersion, EvidenceByDimension: map[string][]domain.ID{}}
	for _, evaluator := range defaultEvaluators {
		signal := evaluator.Evaluate(c)
		if !signal.Available {
			continue
		}
		v.AvailableDimensions = append(v.AvailableDimensions, signal.Dimension)
		v.EvidenceByDimension[signal.Dimension] = appendUnique(nil, signal.Evidence...)
		switch signal.Dimension {
		case "execution":
			v.ExecutionRelevance = signal.Value
		case "change":
			v.ChangeRelevance = signal.Value
		case "dependency":
			v.DependencyRelevance = signal.Value
		case "behavioural":
			v.BehaviouralRelevance = signal.Value
		case "historical":
			v.HistoricalRelevance = signal.Value
		case "runtime":
			v.RuntimeRelevance = signal.Value
		}
	}
	return v
}
