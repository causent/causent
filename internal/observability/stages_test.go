package observability

import (
	"errors"
	"testing"
	"time"
)

func TestMetricsStageTimingAndFirstFinding(t *testing.T) {
	m := NewMetrics("inv-1")
	h := m.Begin(StageRepositoryOverview)
	time.Sleep(5 * time.Millisecond)
	h.Count("files", 3)
	h.Done("completed", nil)
	m.MarkFirstFinding()
	m.MarkFirstFinding() // idempotent
	m.RecordCacheHit()
	m.RecordCacheMiss()
	m.Finish(true, false)
	clone := m.Clone()
	if clone.TimeToFirstFinding <= 0 {
		t.Fatal("expected first finding timing")
	}
	if clone.CacheHits != 1 || clone.CacheMisses != 1 {
		t.Fatalf("cache stats=%d/%d", clone.CacheHits, clone.CacheMisses)
	}
	if len(clone.Stages) != 1 || clone.Stages[0].Counts["files"] != 3 {
		t.Fatalf("stages=%#v", clone.Stages)
	}
	if !clone.Partial || clone.TotalDuration <= 0 {
		t.Fatalf("finish state partial=%t duration=%s", clone.Partial, clone.TotalDuration)
	}
}

func TestMetricsActionLedgerUsesPersistedStatusesAndEvidence(t *testing.T) {
	m := NewMetrics("inv")
	m.SetInvestigationActionLedger([]ActionLedgerEntry{
		{Status: "completed", EvidenceIDs: []string{"e1", "e2"}},
		{Status: "partial", EvidenceIDs: []string{"e3"}},
	})
	got := m.Clone()
	if got.InvestigationActions != 2 || got.InvestigationEvidenceReferences != 3 {
		t.Fatalf("action metrics: actions=%d evidence_references=%d", got.InvestigationActions, got.InvestigationEvidenceReferences)
	}
	if got.InvestigationActionStatuses["completed"] != 1 || got.InvestigationActionStatuses["partial"] != 1 {
		t.Fatalf("action statuses=%v", got.InvestigationActionStatuses)
	}
}

func TestStageHandleRecordsFailure(t *testing.T) {
	m := NewMetrics("inv")
	h := m.Begin(StageIndexing)
	h.Done("completed", errors.New("boom"))
	if m.Stages[0].Outcome != "failed" || m.Stages[0].Error != "boom" {
		t.Fatalf("stage=%#v", m.Stages[0])
	}
}
