package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/causent/malenia/internal/domain"
)

// FileChange describes a path-level delta between revisions.
type FileChange struct {
	Path     string
	OldPath  string // set for renames
	Status   string // added, modified, deleted, renamed
	Language string
}

// IncrementalResult records what was reused versus recomputed.
type IncrementalResult struct {
	Snapshot       Snapshot
	BaseRevisionID string
	ReusedFiles    int
	ReparsedFiles  int
	DeletedFiles   int
	RenamedFiles   int
	CoverageNotes  []string
	Duration       time.Duration
}

// DiffFiles returns path-level changes between two commits using git.
// Renames are detected with git similarity. Missing git output yields an error
// so callers can fall back to a full analyze.
func DiffFiles(ctx context.Context, root, baseSHA, headSHA string) ([]FileChange, error) {
	if baseSHA == "" || headSHA == "" {
		return nil, fmt.Errorf("base and head commit SHAs are required")
	}
	cmd := exec.CommandContext(ctx, "git", "-C", root, "diff", "--name-status", "--find-renames", "-z", baseSHA, headSHA)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git diff: %w", err)
	}
	var changes []FileChange
	fields := strings.Split(string(out), "\x00")
	for i := 0; i < len(fields); {
		status := fields[i]
		i++
		if status == "" {
			continue
		}
		if i >= len(fields) {
			break
		}
		path := fields[i]
		i++
		change := FileChange{Path: path, Language: language(filepath.Ext(path))}
		switch {
		case strings.HasPrefix(status, "R") && i < len(fields):
			change.Status = "renamed"
			change.OldPath = path
			change.Path = fields[i]
			i++
			change.Language = language(filepath.Ext(change.Path))
		case status == "A":
			change.Status = "added"
		case status == "D":
			change.Status = "deleted"
		case status == "M", status == "T":
			change.Status = "modified"
		default:
			change.Status = "modified"
		}
		if change.Language == "" && change.Status != "deleted" {
			continue
		}
		changes = append(changes, change)
	}
	return changes, nil
}

// AnalyzeIncremental updates a base snapshot for a new revision by reparsing
// only affected files, then rebuilding relationships. When the base snapshot is
// empty or incomplete, callers should use Analyze instead.
func (a Analyzer) AnalyzeIncremental(ctx context.Context, root, repositoryID, revisionID, commitSHA string, base Snapshot, changes []FileChange) (IncrementalResult, error) {
	started := time.Now()
	result := IncrementalResult{
		BaseRevisionID: base.RevisionID,
		CoverageNotes: []string{
			"incremental update reuses unaffected file nodes from the base revision",
			"relationships are rebuilt for the resulting snapshot; missing base coverage is not negative evidence",
		},
	}
	if a.MaxFiles <= 0 {
		a.MaxFiles = 10000
	}
	if a.MaxBytes <= 0 {
		a.MaxBytes = 2 << 20
	}
	if base.RepositoryID == "" || len(base.Nodes) == 0 {
		snap, err := a.Analyze(ctx, root, repositoryID, revisionID, commitSHA)
		result.Snapshot = snap
		result.ReparsedFiles = countFiles(snap)
		result.Duration = time.Since(started)
		result.CoverageNotes = append(result.CoverageNotes, "fell back to full analyze because base snapshot was empty")
		return result, err
	}

	affected := map[string]FileChange{}
	deleted := map[string]bool{}
	renames := map[string]string{} // old -> new
	for _, change := range changes {
		switch change.Status {
		case "deleted":
			deleted[filepath.ToSlash(change.Path)] = true
			result.DeletedFiles++
		case "renamed":
			oldPath := filepath.ToSlash(change.OldPath)
			newPath := filepath.ToSlash(change.Path)
			deleted[oldPath] = true
			renames[oldPath] = newPath
			affected[newPath] = change
			result.RenamedFiles++
		default:
			path := filepath.ToSlash(change.Path)
			affected[path] = change
		}
	}

	out := Snapshot{RepositoryID: repositoryID, RevisionID: revisionID, CommitSHA: commitSHA}
	contents := map[string]string{}
	keptFiles := map[string]bool{}

	// Reuse unaffected file bodies by reading only when needed for relationship rebuild.
	for _, node := range base.Nodes {
		if node.Type != "File" {
			continue
		}
		path := filepath.ToSlash(node.FilePath)
		if deleted[path] || affected[path].Path != "" {
			continue
		}
		keptFiles[path] = true
		result.ReusedFiles++
	}

	// Re-read kept files and re-extract symbols/imports under the new revision ID.
	// File discovery is reused from the base snapshot; only path membership changes.
	keptPaths := make([]string, 0, len(keptFiles))
	for path := range keptFiles {
		keptPaths = append(keptPaths, path)
	}
	sort.Strings(keptPaths)
	for _, path := range keptPaths {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		data, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			result.CoverageNotes = append(result.CoverageNotes, "missing reused file "+path+"; skipped")
			delete(keptFiles, path)
			result.ReusedFiles--
			continue
		}
		if len(data) > a.MaxBytes {
			continue
		}
		lang := language(filepath.Ext(path))
		if lang == "" {
			continue
		}
		text := string(data)
		contents[path] = text
		digest := sha256.Sum256(data)
		fileID := nodeID(repositoryID, revisionID, "file", path)
		out.Nodes = append(out.Nodes, domain.ProgramNode{
			ID: fileID, RepositoryID: repositoryID, RevisionID: revisionID, Type: "File",
			Name: path, Identity: lang + ":" + path, FilePath: path, Language: lang,
			StartLine: 1, EndLine: strings.Count(text, "\n") + 1, ContentDigest: hex.EncodeToString(digest[:]),
		})
		a.extractFile(text, path, lang, fileID, &out)
	}

	// Reparse added/modified/renamed targets.
	reparsePaths := make([]string, 0, len(affected))
	for path := range affected {
		reparsePaths = append(reparsePaths, path)
	}
	sort.Strings(reparsePaths)
	for _, path := range reparsePaths {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		full := filepath.Join(root, path)
		data, err := os.ReadFile(full)
		if err != nil {
			result.CoverageNotes = append(result.CoverageNotes, "could not read changed file "+path)
			continue
		}
		if len(data) > a.MaxBytes {
			continue
		}
		lang := language(filepath.Ext(path))
		if lang == "" {
			continue
		}
		text := string(data)
		contents[path] = text
		digest := sha256.Sum256(data)
		fileID := nodeID(repositoryID, revisionID, "file", path)
		out.Nodes = append(out.Nodes, domain.ProgramNode{
			ID: fileID, RepositoryID: repositoryID, RevisionID: revisionID, Type: "File",
			Name: path, Identity: lang + ":" + path, FilePath: path, Language: lang,
			StartLine: 1, EndLine: strings.Count(text, "\n") + 1, ContentDigest: hex.EncodeToString(digest[:]), Changed: true,
		})
		a.extractFile(text, path, lang, fileID, &out)
		result.ReparsedFiles++
	}

	a.buildReferences(contents, &out)
	result.Snapshot = out
	result.Duration = time.Since(started)
	return result, nil
}

func countFiles(s Snapshot) int {
	n := 0
	for _, node := range s.Nodes {
		if node.Type == "File" {
			n++
		}
	}
	return n
}

// SnapshotConsistency compares two snapshots for the same revision content.
// File identities and symbol identities must match; relationship IDs may differ
// only if both sides contain equivalent typed edges.
func SnapshotConsistency(full, incremental Snapshot) []string {
	var problems []string
	fullFiles := identitiesByType(full, "File")
	incFiles := identitiesByType(incremental, "File")
	for id := range fullFiles {
		if _, ok := incFiles[id]; !ok {
			problems = append(problems, "incremental missing file "+id)
		}
	}
	for id := range incFiles {
		if _, ok := fullFiles[id]; !ok {
			problems = append(problems, "incremental extra file "+id)
		}
	}
	fullSymbols := identitiesByType(full, "Function", "Method", "Test", "Class")
	incSymbols := identitiesByType(incremental, "Function", "Method", "Test", "Class")
	for id := range fullSymbols {
		if _, ok := incSymbols[id]; !ok {
			problems = append(problems, "incremental missing symbol "+id)
		}
	}
	for id := range incSymbols {
		if _, ok := fullSymbols[id]; !ok {
			problems = append(problems, "incremental extra symbol "+id)
		}
	}
	sort.Strings(problems)
	return problems
}

func identitiesByType(s Snapshot, types ...string) map[string]domain.ProgramNode {
	allowed := map[string]bool{}
	for _, t := range types {
		allowed[t] = true
	}
	out := map[string]domain.ProgramNode{}
	for _, node := range s.Nodes {
		if allowed[node.Type] {
			out[node.Identity] = node
		}
	}
	return out
}
