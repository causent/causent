package cache

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writeCorrupt(path string) error {
	return os.WriteFile(path, []byte("{not-json"), 0o644)
}

type sample struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

func TestFSCacheRoundTripAndMiss(t *testing.T) {
	c, err := OpenFS(filepath.Join(t.TempDir(), "cache"))
	if err != nil {
		t.Fatal(err)
	}
	key := Key{RepositoryID: "repo", CommitSHA: "abc", AnalyzerVersion: AnalyzerVersion, ArtifactType: ArtifactOverview, ArtifactID: "overview"}
	if err := c.Get(key, &sample{}); !errors.Is(err, ErrMiss) {
		t.Fatalf("expected miss, got %v", err)
	}
	if err := c.Put(key, sample{Name: "demo", Count: 3}); err != nil {
		t.Fatal(err)
	}
	var got sample
	if err := c.Get(key, &got); err != nil {
		t.Fatal(err)
	}
	if got.Name != "demo" || got.Count != 3 {
		t.Fatalf("unexpected value %#v", got)
	}
	stats := c.Stats()
	if stats.Hits != 1 || stats.Misses != 1 {
		t.Fatalf("stats=%#v", stats)
	}
}

func TestDisabledCacheFallsBack(t *testing.T) {
	c, err := OpenFS("")
	if err != nil {
		t.Fatal(err)
	}
	key := Key{RepositoryID: "r", CommitSHA: "c", AnalyzerVersion: AnalyzerVersion, ArtifactType: ArtifactSnapshot, ArtifactID: "s"}
	if err := c.Put(key, sample{}); !errors.Is(err, ErrDisabled) {
		t.Fatalf("expected disabled, got %v", err)
	}
	if err := c.Get(key, &sample{}); !errors.Is(err, ErrDisabled) {
		t.Fatalf("expected disabled get, got %v", err)
	}
}

func TestCorruptEntryIsRemoved(t *testing.T) {
	root := filepath.Join(t.TempDir(), "cache")
	c, err := OpenFS(root)
	if err != nil {
		t.Fatal(err)
	}
	key := Key{RepositoryID: "repo", CommitSHA: "abc", AnalyzerVersion: AnalyzerVersion, ArtifactType: ArtifactOverview, ArtifactID: "overview"}
	path := c.pathFor(key)
	if err := c.Put(key, sample{Name: "ok"}); err != nil {
		t.Fatal(err)
	}
	if err := writeCorrupt(path); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(key, &sample{}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("expected corrupt, got %v", err)
	}
	if _, err := OpenFS(root); err != nil {
		t.Fatal(err)
	}
}
