package engine

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/causent/causent/internal/domain"
	"github.com/causent/causent/internal/persistence"
)

func TestLargeEvidenceIsStoredAsVerifiedArtifact(t *testing.T) {
	store, err := persistence.Open(filepath.Join(t.TempDir(), "artifacts.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC()
	inv := domain.Investigation{
		ID:        domain.NewID(),
		RepoPath:  "/repo",
		Command:   []string{"go", "test"},
		Status:    domain.StatusCreated,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := store.SaveInvestigation(inv); err != nil {
		t.Fatalf("save investigation: %v", err)
	}

	full := strings.Repeat("stack frame line\n", 2000) // ~34 KB, above the inline bound
	ev := domain.Evidence{
		ID:              domain.NewID(),
		InvestigationID: inv.ID,
		Type:            domain.EvidenceStackTrace,
		Source:          "command_stderr",
		Timestamp:       now,
		ContentRef:      "stderr_output",
		Payload:         full,
	}

	investigator := &Investigator{Store: store}
	investigator.attachArtifact(&ev)

	if ev.ArtifactID == "" {
		t.Fatal("expected artifact reference for large evidence")
	}
	if len(ev.Payload) > maxInlineEvidenceBytes+256 {
		t.Fatalf("inline payload not bounded: %d bytes", len(ev.Payload))
	}
	if !strings.Contains(ev.Payload, "truncated") {
		t.Fatalf("expected truncation marker, got %q", ev.Payload)
	}
	if !strings.HasPrefix(ev.ContentRef, "artifact:") {
		t.Fatalf("content ref = %q, want artifact reference", ev.ContentRef)
	}

	art, err := store.GetArtifact(ev.ArtifactID)
	if err != nil {
		t.Fatalf("get artifact: %v", err)
	}
	if art.Size != int64(len(full)) {
		t.Fatalf("artifact size = %d, want %d", art.Size, len(full))
	}
	if art.Digest != ev.Digest {
		t.Fatalf("artifact digest does not match evidence digest")
	}

	data, err := store.ReadArtifactData(art)
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}
	if string(data) != full {
		t.Fatal("artifact contents do not match the original evidence payload")
	}

	// Evidence must survive the round trip with its artifact reference intact.
	if err := store.SaveEvidence(ev); err != nil {
		t.Fatalf("save evidence: %v", err)
	}
	stored, err := store.ListEvidence(inv.ID)
	if err != nil {
		t.Fatalf("list evidence: %v", err)
	}
	if len(stored) != 1 || stored[0].ArtifactID != ev.ArtifactID {
		t.Fatalf("evidence artifact reference lost: %+v", stored)
	}
}

func TestSmallEvidenceStaysInline(t *testing.T) {
	store, err := persistence.Open(filepath.Join(t.TempDir(), "inline.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ev := domain.Evidence{
		ID:              domain.NewID(),
		InvestigationID: domain.NewID(),
		Type:            domain.EvidenceReproduction,
		Payload:         "exit_code=7",
	}
	(&Investigator{Store: store}).attachArtifact(&ev)
	if ev.ArtifactID != "" {
		t.Fatalf("small payload should stay inline, got artifact %s", ev.ArtifactID)
	}
	if ev.Payload != "exit_code=7" {
		t.Fatalf("payload modified: %q", ev.Payload)
	}
}
