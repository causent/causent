// Package investigation contains the durable contracts for adaptive work.
// Scheduling policy remains replaceable; this package does not impose a fixed
// prompt chain or DAG.
package investigation

import (
	"context"
	"fmt"
	"github.com/causent/malenia/internal/domain"
	"sort"
	"time"
)

type ActionInput struct {
	InvestigationID domain.ID
	References      []string
	Metadata        map[string]string
}
type ActionOutput struct {
	References []string
	Metadata   map[string]string
	Evidence   []domain.Evidence
}
type ActionDefinition struct {
	ID                   string
	Type                 string
	Description          string
	InputSchema          string
	OutputSchema         string
	RequiredEvidence     []string
	Preconditions        []string
	ResourceRequirements map[string]string
	ExecutionRisk        string
	Timeout              time.Duration
	RetryLimit           int
	Idempotent           bool
}
type Action interface {
	Type() string
	Definition() ActionDefinition
	Execute(context.Context, ActionInput) (ActionOutput, error)
}
type Registry struct{ actions map[string]Action }

func NewRegistry() *Registry { return &Registry{actions: map[string]Action{}} }
func (r *Registry) Register(action Action) error {
	if action == nil || action.Type() == "" {
		return fmt.Errorf("action type is required")
	}
	if _, ok := r.actions[action.Type()]; ok {
		return fmt.Errorf("action %q already registered", action.Type())
	}
	r.actions[action.Type()] = action
	return nil
}
func (r *Registry) Get(kind string) (Action, bool) { a, ok := r.actions[kind]; return a, ok }
func (r *Registry) Definitions() []ActionDefinition {
	out := make([]ActionDefinition, 0, len(r.actions))
	for _, a := range r.actions {
		out = append(out, a.Definition())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}
func DependenciesReady(activity domain.Activity, completed map[string]bool) bool {
	for _, id := range activity.DependencyIDs {
		if !completed[id] {
			return false
		}
	}
	return true
}
func NewActivity(inv domain.ID, id, kind string, deps []string, inputs []string) domain.Activity {
	status := domain.ActivityReady
	if len(deps) > 0 {
		status = domain.ActivityPending
	}
	return domain.Activity{ID: id, InvestigationID: inv, Type: kind, Status: status, DependencyIDs: deps, InputRefs: inputs, AttemptCount: 0}
}
func Complete(activity domain.Activity, outputs []string) domain.Activity {
	now := time.Now().UTC()
	activity.Status = domain.ActivityCompleted
	activity.OutputRefs = outputs
	activity.CompletedAt = &now
	return activity
}
func Fail(activity domain.Activity, err error) domain.Activity {
	now := time.Now().UTC()
	activity.Status = domain.ActivityFailed
	activity.Error = err.Error()
	activity.CompletedAt = &now
	return activity
}
