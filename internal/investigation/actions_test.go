package investigation

import (
	"github.com/causent/causent/internal/domain"
	"testing"
)

func TestActivityDependenciesAndTransitions(t *testing.T) {
	a := NewActivity("inv", "a", "InspectSymbol", nil, nil)
	b := NewActivity("inv", "b", "FindReferences", []string{"a"}, nil)
	if a.Status != domain.ActivityReady || b.Status != domain.ActivityPending {
		t.Fatalf("statuses=%s,%s", a.Status, b.Status)
	}
	if DependenciesReady(b, map[string]bool{"a": false}) {
		t.Fatal("blocked dependency marked ready")
	}
	if !DependenciesReady(b, map[string]bool{"a": true}) {
		t.Fatal("completed dependency not ready")
	}
	b = Complete(b, []string{"out"})
	if b.Status != domain.ActivityCompleted || len(b.OutputRefs) != 1 {
		t.Fatalf("completed=%#v", b)
	}
}
