// Package observability records stage-level timings and counters for diagnosis.
// Metrics are facts about the investigation process, not diagnostic conclusions.
package observability

import (
	"encoding/json"
	"sync"
	"time"
)

// Stage names for the demand-driven investigation pipeline.
const (
	StageRepositoryOverview   = "repository_overview"
	StageFailureIngestion     = "failure_ingestion"
	StageFailureGrouping      = "failure_grouping"
	StageIndexing             = "repository_indexing"
	StagePersistence          = "architecture_persistence"
	StageIncrementalIndexing  = "incremental_indexing"
	StageCandidateGeneration  = "candidate_generation"
	StageHypothesisGeneration = "hypothesis_generation"
	StagePreliminaryDiagnosis = "preliminary_diagnosis"
	StageAdaptiveDeep         = "adaptive_deep_investigation"
	StageReproduction         = "reproduction"
	StageBaseComparison       = "base_comparison"
	StageLocalization         = "localization"
	StageBundlePublish        = "bundle_publish"
)

// StageRecord is one timed stage execution.
type StageRecord struct {
	Name       string            `json:"name"`
	StartedAt  time.Time         `json:"started_at"`
	FinishedAt time.Time         `json:"finished_at"`
	Duration   time.Duration     `json:"duration"`
	Outcome    string            `json:"outcome"` // completed, skipped, failed, cancelled, inconclusive
	Counts     map[string]int    `json:"counts,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	Error      string            `json:"error,omitempty"`
}

// Metrics aggregates process instrumentation for one investigation.
type Metrics struct {
	mu sync.Mutex

	InvestigationID      string        `json:"investigation_id"`
	StartedAt            time.Time     `json:"started_at"`
	FinishedAt           time.Time     `json:"finished_at,omitempty"`
	TotalDuration        time.Duration `json:"total_duration,omitempty"`
	TimeToFirstFinding   time.Duration `json:"time_to_first_useful_finding,omitempty"`
	FirstFindingAt       time.Time     `json:"first_finding_at,omitempty"`
	CacheHits            int           `json:"cache_hits"`
	CacheMisses          int           `json:"cache_misses"`
	FilesProcessed       int           `json:"files_processed"`
	SymbolsProcessed     int           `json:"symbols_processed"`
	InvestigationActions int           `json:"investigation_actions"`
	Experiments          int           `json:"experiments"`
	Partial              bool          `json:"partial"`
	Inconclusive         bool          `json:"inconclusive"`
	Stages               []StageRecord `json:"stages"`
}

// NewMetrics starts instrumentation for one investigation.
func NewMetrics(investigationID string) *Metrics {
	return &Metrics{InvestigationID: investigationID, StartedAt: time.Now().UTC()}
}

// Begin starts a stage timer. Call Done on the returned handle.
func (m *Metrics) Begin(name string) *StageHandle {
	if m == nil {
		return &StageHandle{name: name, started: time.Now().UTC()}
	}
	return &StageHandle{metrics: m, name: name, started: time.Now().UTC(), counts: map[string]int{}, metadata: map[string]string{}}
}

// StageHandle records one in-flight stage.
type StageHandle struct {
	metrics  *Metrics
	name     string
	started  time.Time
	counts   map[string]int
	metadata map[string]string
}

// Count increments a named counter for the stage.
func (h *StageHandle) Count(key string, n int) {
	if h == nil {
		return
	}
	if h.counts == nil {
		h.counts = map[string]int{}
	}
	h.counts[key] += n
}

// Meta records a string attribute for the stage.
func (h *StageHandle) Meta(key, value string) {
	if h == nil {
		return
	}
	if h.metadata == nil {
		h.metadata = map[string]string{}
	}
	h.metadata[key] = value
}

// Done finalizes the stage with an outcome and optional error.
func (h *StageHandle) Done(outcome string, err error) {
	if h == nil {
		return
	}
	finished := time.Now().UTC()
	rec := StageRecord{
		Name:       h.name,
		StartedAt:  h.started,
		FinishedAt: finished,
		Duration:   finished.Sub(h.started),
		Outcome:    outcome,
		Counts:     h.counts,
		Metadata:   h.metadata,
	}
	if err != nil {
		rec.Error = err.Error()
		if outcome == "" || outcome == "completed" {
			rec.Outcome = "failed"
		}
	}
	if h.metrics == nil {
		return
	}
	h.metrics.mu.Lock()
	defer h.metrics.mu.Unlock()
	h.metrics.Stages = append(h.metrics.Stages, rec)
	switch h.name {
	case StageIndexing, StageIncrementalIndexing, StageRepositoryOverview:
		h.metrics.FilesProcessed += rec.Counts["files"]
		h.metrics.SymbolsProcessed += rec.Counts["symbols"]
	case StageAdaptiveDeep:
		h.metrics.InvestigationActions += rec.Counts["actions"]
		h.metrics.Experiments += rec.Counts["experiments"]
	}
}

// RecordCacheHit increments cache hit count.
func (m *Metrics) RecordCacheHit() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.CacheHits++
	m.mu.Unlock()
}

// RecordCacheMiss increments cache miss count.
func (m *Metrics) RecordCacheMiss() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.CacheMisses++
	m.mu.Unlock()
}

// MarkFirstFinding records time-to-first-useful-finding once.
func (m *Metrics) MarkFirstFinding() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.FirstFindingAt.IsZero() {
		return
	}
	m.FirstFindingAt = time.Now().UTC()
	m.TimeToFirstFinding = m.FirstFindingAt.Sub(m.StartedAt)
}

// Finish closes overall investigation timing.
func (m *Metrics) Finish(partial, inconclusive bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.FinishedAt = time.Now().UTC()
	m.TotalDuration = m.FinishedAt.Sub(m.StartedAt)
	m.Partial = partial
	m.Inconclusive = inconclusive
}

// Clone returns a snapshot safe for serialization.
func (m *Metrics) Clone() Metrics {
	if m == nil {
		return Metrics{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return Metrics{
		InvestigationID:      m.InvestigationID,
		StartedAt:            m.StartedAt,
		FinishedAt:           m.FinishedAt,
		TotalDuration:        m.TotalDuration,
		TimeToFirstFinding:   m.TimeToFirstFinding,
		FirstFindingAt:       m.FirstFindingAt,
		CacheHits:            m.CacheHits,
		CacheMisses:          m.CacheMisses,
		FilesProcessed:       m.FilesProcessed,
		SymbolsProcessed:     m.SymbolsProcessed,
		InvestigationActions: m.InvestigationActions,
		Experiments:          m.Experiments,
		Partial:              m.Partial,
		Inconclusive:         m.Inconclusive,
		Stages:               append([]StageRecord(nil), m.Stages...),
	}
}

// JSON serializes metrics for bundle inclusion.
func (m *Metrics) JSON() ([]byte, error) {
	clone := m.Clone()
	return json.MarshalIndent(struct {
		InvestigationID      string        `json:"investigation_id"`
		StartedAt            time.Time     `json:"started_at"`
		FinishedAt           time.Time     `json:"finished_at,omitempty"`
		TotalDuration        time.Duration `json:"total_duration,omitempty"`
		TimeToFirstFinding   time.Duration `json:"time_to_first_useful_finding,omitempty"`
		FirstFindingAt       time.Time     `json:"first_finding_at,omitempty"`
		CacheHits            int           `json:"cache_hits"`
		CacheMisses          int           `json:"cache_misses"`
		FilesProcessed       int           `json:"files_processed"`
		SymbolsProcessed     int           `json:"symbols_processed"`
		InvestigationActions int           `json:"investigation_actions"`
		Experiments          int           `json:"experiments"`
		Partial              bool          `json:"partial"`
		Inconclusive         bool          `json:"inconclusive"`
		Stages               []StageRecord `json:"stages"`
	}{
		InvestigationID:      clone.InvestigationID,
		StartedAt:            clone.StartedAt,
		FinishedAt:           clone.FinishedAt,
		TotalDuration:        clone.TotalDuration,
		TimeToFirstFinding:   clone.TimeToFirstFinding,
		FirstFindingAt:       clone.FirstFindingAt,
		CacheHits:            clone.CacheHits,
		CacheMisses:          clone.CacheMisses,
		FilesProcessed:       clone.FilesProcessed,
		SymbolsProcessed:     clone.SymbolsProcessed,
		InvestigationActions: clone.InvestigationActions,
		Experiments:          clone.Experiments,
		Partial:              clone.Partial,
		Inconclusive:         clone.Inconclusive,
		Stages:               clone.Stages,
	}, "", "  ")
}

// DurationOf returns the sum of durations for stages with the given name.
func (m *Metrics) DurationOf(name string) time.Duration {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var total time.Duration
	for _, stage := range m.Stages {
		if stage.Name == name {
			total += stage.Duration
		}
	}
	return total
}
