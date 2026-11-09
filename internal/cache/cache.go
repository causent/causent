// Package cache provides a backend-independent artifact cache.
// Repository artifacts may be shared across investigations. Diagnostic
// conclusions must not be stored here as universal facts.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// AnalyzerVersion must bump when snapshot/overview formats change.
	AnalyzerVersion  = "repo-analyzer-v1"
	ArtifactOverview = "repository_overview"
	ArtifactSnapshot = "repository_snapshot"
)

var (
	ErrMiss     = errors.New("cache miss")
	ErrCorrupt  = errors.New("cache entry corrupt")
	ErrDisabled = errors.New("cache disabled")
)

// Key identifies an immutable repository artifact.
type Key struct {
	RepositoryID    string
	CommitSHA       string
	AnalyzerVersion string
	ArtifactType    string
	ArtifactID      string
}

func (k Key) String() string {
	raw := k.RepositoryID + "\x00" + k.CommitSHA + "\x00" + k.AnalyzerVersion + "\x00" + k.ArtifactType + "\x00" + k.ArtifactID
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// Stats tracks hit/miss counters for instrumentation.
type Stats struct {
	Hits   int
	Misses int
}

// Cache stores immutable repository artifacts.
type Cache interface {
	Get(key Key, dst any) error
	Put(key Key, value any) error
	Delete(key Key) error
	Stats() Stats
}

// FSCache is a filesystem-backed cache with safe concurrent access per process.
type FSCache struct {
	root    string
	mu      sync.Mutex
	fileMu  sync.Map // key path -> *sync.Mutex
	hits    int
	misses  int
	enabled bool
}

// OpenFS creates or opens a filesystem cache under root. An empty root disables the cache.
func OpenFS(root string) (*FSCache, error) {
	if root == "" {
		return &FSCache{enabled: false}, nil
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	return &FSCache{root: root, enabled: true}, nil
}

func (c *FSCache) pathFor(key Key) string {
	id := key.String()
	return filepath.Join(c.root, key.ArtifactType, id[:2], id+".json")
}

func (c *FSCache) lock(path string) *sync.Mutex {
	actual, _ := c.fileMu.LoadOrStore(path, &sync.Mutex{})
	return actual.(*sync.Mutex)
}

// Get loads a cached artifact. Returns ErrMiss when absent and ErrCorrupt when unreadable.
func (c *FSCache) Get(key Key, dst any) error {
	if c == nil || !c.enabled {
		return ErrDisabled
	}
	path := c.pathFor(key)
	mu := c.lock(path)
	mu.Lock()
	defer mu.Unlock()
	data, err := os.ReadFile(path)
	if err != nil {
		c.mu.Lock()
		c.misses++
		c.mu.Unlock()
		if errors.Is(err, fs.ErrNotExist) {
			return ErrMiss
		}
		return err
	}
	var envelope entry
	if err := json.Unmarshal(data, &envelope); err != nil {
		_ = os.Remove(path)
		c.mu.Lock()
		c.misses++
		c.mu.Unlock()
		return fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if envelope.Key != key.String() || envelope.AnalyzerVersion != key.AnalyzerVersion || envelope.ArtifactType != key.ArtifactType {
		_ = os.Remove(path)
		c.mu.Lock()
		c.misses++
		c.mu.Unlock()
		return ErrCorrupt
	}
	if err := json.Unmarshal(envelope.Payload, dst); err != nil {
		_ = os.Remove(path)
		c.mu.Lock()
		c.misses++
		c.mu.Unlock()
		return fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	c.mu.Lock()
	c.hits++
	c.mu.Unlock()
	return nil
}

// Put stores an immutable artifact. Existing entries with the same key are replaced.
func (c *FSCache) Put(key Key, value any) error {
	if c == nil || !c.enabled {
		return ErrDisabled
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	envelope := entry{
		Key:             key.String(),
		RepositoryID:    key.RepositoryID,
		CommitSHA:       key.CommitSHA,
		AnalyzerVersion: key.AnalyzerVersion,
		ArtifactType:    key.ArtifactType,
		ArtifactID:      key.ArtifactID,
		StoredAt:        time.Now().UTC(),
		Payload:         payload,
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	path := c.pathFor(key)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	mu := c.lock(path)
	mu.Lock()
	defer mu.Unlock()
	tmpFile, err := os.CreateTemp(filepath.Dir(path), ".malenia-cache-*")
	if err != nil {
		return err
	}
	tmp := tmpFile.Name()
	if err := tmpFile.Chmod(0o644); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmp)
		return err
	}
	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// Delete removes a cached artifact.
func (c *FSCache) Delete(key Key) error {
	if c == nil || !c.enabled {
		return nil
	}
	path := c.pathFor(key)
	mu := c.lock(path)
	mu.Lock()
	defer mu.Unlock()
	err := os.Remove(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// Stats returns hit/miss counters.
func (c *FSCache) Stats() Stats {
	if c == nil {
		return Stats{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return Stats{Hits: c.hits, Misses: c.misses}
}

type entry struct {
	Key             string          `json:"key"`
	RepositoryID    string          `json:"repository_id"`
	CommitSHA       string          `json:"commit_sha"`
	AnalyzerVersion string          `json:"analyzer_version"`
	ArtifactType    string          `json:"artifact_type"`
	ArtifactID      string          `json:"artifact_id"`
	StoredAt        time.Time       `json:"stored_at"`
	Payload         json.RawMessage `json:"payload"`
}
