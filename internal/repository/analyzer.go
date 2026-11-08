// Package repository builds a bounded, revision-aware repository/program graph.
// It uses syntax-shaped extraction rather than pretending to be a compiler.
package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/causent/causent/internal/domain"
)

type Snapshot struct {
	RepositoryID   string
	RevisionID     string
	CommitSHA      string
	Nodes          []domain.ProgramNode
	Relationships  []domain.Relationship
	ChangedSymbols []string
}

type Analyzer struct {
	MaxFiles int
	MaxBytes int
}

func (a Analyzer) Analyze(ctx context.Context, root, repositoryID, revisionID, commitSHA string) (Snapshot, error) {
	if root == "" || repositoryID == "" || revisionID == "" {
		return Snapshot{}, fmt.Errorf("repository root, repository id, and revision id are required")
	}
	if a.MaxFiles <= 0 {
		a.MaxFiles = 10000
	}
	if a.MaxBytes <= 0 {
		a.MaxBytes = 2 << 20
	}
	s := Snapshot{RepositoryID: repositoryID, RevisionID: revisionID, CommitSHA: commitSHA}
	contents := map[string]string{}
	var files []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if entry.IsDir() {
			if path != root && excludedDir(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if len(files) >= a.MaxFiles || excludedDir(filepath.Base(filepath.Dir(path))) {
			return nil
		}
		if language(filepath.Ext(path)) != "" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return s, err
	}
	sort.Strings(files)
	for _, path := range files {
		if ctx.Err() != nil {
			return s, ctx.Err()
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return s, err
		}
		if len(data) > a.MaxBytes {
			continue
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			continue
		}
		text := string(data)
		contents[rel] = text
		lang := language(filepath.Ext(path))
		digest := sha256.Sum256(data)
		fileID := nodeID(repositoryID, revisionID, "file", rel)
		s.Nodes = append(s.Nodes, domain.ProgramNode{ID: fileID, RepositoryID: repositoryID, RevisionID: revisionID, Type: "File", Name: rel, Identity: lang + ":" + rel, FilePath: rel, Language: lang, StartLine: 1, EndLine: strings.Count(text, "\n") + 1, ContentDigest: hex.EncodeToString(digest[:])})
		a.extractFile(text, rel, lang, fileID, &s)
	}
	a.buildReferences(contents, &s)
	return s, nil
}

func excludedDir(name string) bool {
	switch name {
	case ".git", ".causent", "vendor", "node_modules", "dist", "build", "target":
		return true
	}
	return false
}
func language(ext string) string {
	switch strings.ToLower(ext) {
	case ".go":
		return "go"
	case ".py":
		return "python"
	case ".js", ".jsx", ".mjs", ".ts", ".tsx":
		return "javascript"
	case ".rs":
		return "rust"
	}
	return ""
}
func nodeID(repo, rev, kind, identity string) string {
	h := sha256.Sum256([]byte(repo + "\x00" + rev + "\x00" + kind + "\x00" + identity))
	return "pn-" + hex.EncodeToString(h[:12])
}
func edgeID(source, typ, target string) string {
	h := sha256.Sum256([]byte(source + "\x00" + typ + "\x00" + target))
	return "pe-" + hex.EncodeToString(h[:12])
}
func addEdge(s *Snapshot, source, sourceType, target, targetType, typ string) {
	s.Relationships = append(s.Relationships, domain.Relationship{ID: edgeID(source, typ, target), SourceType: sourceType, SourceID: source, TargetType: targetType, TargetID: target, Type: typ, RevisionID: s.RevisionID})
}

var (
	goFunc   = regexp.MustCompile(`(?m)^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\(`)
	goType   = regexp.MustCompile(`(?m)^\s*type\s+([A-Za-z_][A-Za-z0-9_]*)\s+(struct|interface)\b`)
	pyFunc   = regexp.MustCompile(`(?m)^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(`)
	pyClass  = regexp.MustCompile(`(?m)^\s*class\s+([A-Za-z_][A-Za-z0-9_]*)\b`)
	jsFunc   = regexp.MustCompile(`(?m)^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(`)
	importRE = regexp.MustCompile(`(?m)^\s*(?:import\s+(?:[^;]+?\s+from\s+)?|from\s+)(["'][^"']+["']|[^\s;]+)`)
)

func (a Analyzer) extractFile(data, rel, lang, fileID string, s *Snapshot) {
	lines := strings.Split(data, "\n")
	digest := sha256.Sum256([]byte(data))
	contentDigest := hex.EncodeToString(digest[:])
	addSymbol := func(name, typ string, line int) {
		identity := lang + ":" + rel + ":" + typ + ":" + name
		id := nodeID(s.RepositoryID, s.RevisionID, "symbol", identity)
		s.Nodes = append(s.Nodes, domain.ProgramNode{ID: id, RepositoryID: s.RepositoryID, RevisionID: s.RevisionID, Type: typ, Name: name, Identity: identity, FilePath: rel, Language: lang, StartLine: line, EndLine: strings.Count(data, "\n") + 1, ContentDigest: contentDigest})
		addEdge(s, fileID, "File", id, typ, "DEFINES")
	}
	var matches [][]int
	switch lang {
	case "go":
		matches = goFunc.FindAllStringSubmatchIndex(data, -1)
		for _, m := range matches {
			addSymbol(data[m[2]:m[3]], symbolType(rel, data[m[0]:m[1]]), lineAt(data, m[0]))
		}
		for _, m := range goType.FindAllStringSubmatchIndex(data, -1) {
			addSymbol(data[m[2]:m[3]], "Class", lineAt(data, m[0]))
		}
	case "python":
		for _, m := range pyFunc.FindAllStringSubmatchIndex(data, -1) {
			addSymbol(data[m[2]:m[3]], testOr("Function", rel, data[m[2]:m[3]]), lineAt(data, m[0]))
		}
		for _, m := range pyClass.FindAllStringSubmatchIndex(data, -1) {
			addSymbol(data[m[2]:m[3]], "Class", lineAt(data, m[0]))
		}
	case "javascript":
		for _, m := range jsFunc.FindAllStringSubmatchIndex(data, -1) {
			addSymbol(data[m[2]:m[3]], "Function", lineAt(data, m[0]))
		}
	}
	for _, m := range importRE.FindAllStringSubmatch(data, -1) {
		if len(m) > 1 {
			target := strings.Trim(m[1], "\"'")
			id := nodeID(s.RepositoryID, s.RevisionID, "dependency", lang+":"+target)
			s.Nodes = append(s.Nodes, domain.ProgramNode{ID: id, RepositoryID: s.RepositoryID, RevisionID: s.RevisionID, Type: "Dependency", Name: target, Identity: lang + ":" + target, Language: lang})
			addEdge(s, fileID, "File", id, "Dependency", "IMPORTS")
		}
	}
	_ = lines
}

func lineAt(data string, offset int) int { return 1 + strings.Count(data[:offset], "\n") }
func symbolType(rel, line string) string {
	if strings.Contains(line, "Test") || strings.HasSuffix(rel, "_test.go") {
		return "Test"
	}
	return "Function"
}
func testOr(normal, rel, name string) string {
	if strings.HasPrefix(name, "test_") || strings.HasSuffix(rel, "_test.py") {
		return "Test"
	}
	return normal
}

func (a Analyzer) buildReferences(contents map[string]string, s *Snapshot) {
	byName := map[string][]domain.ProgramNode{}
	for _, n := range s.Nodes {
		if n.Type == "Function" || n.Type == "Method" || n.Type == "Test" || n.Type == "Class" {
			byName[n.Name] = append(byName[n.Name], n)
		}
	}
	seen := map[string]bool{}
	for _, file := range s.Nodes {
		if file.Type != "File" {
			continue
		}
		data := contents[file.FilePath]
		for name, targets := range byName {
			if !regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`).MatchString(data) {
				continue
			}
			for _, target := range targets {
				for _, source := range s.Nodes {
					if source.FilePath != file.FilePath || (source.Type != "Function" && source.Type != "Method" && source.Type != "Test") || source.ID == target.ID {
						continue
					}
					typ := "REFERENCES"
					if source.Type == "Test" && target.Type != "Test" {
						typ = "TESTS"
					} else if strings.Contains(data, name+"(") {
						typ = "CALLS"
					}
					key := source.ID + ":" + typ + ":" + target.ID
					if !seen[key] {
						addEdge(s, source.ID, source.Type, target.ID, target.Type, typ)
						seen[key] = true
					}
				}
			}
		}
	}
}

func Compare(a, b Snapshot) (added, removed, changed []string) {
	am := map[string]domain.ProgramNode{}
	bm := map[string]domain.ProgramNode{}
	for _, n := range a.Nodes {
		if n.Type != "File" {
			am[n.Identity] = n
		}
	}
	for _, n := range b.Nodes {
		if n.Type != "File" {
			bm[n.Identity] = n
		}
	}
	for id, n := range bm {
		if old, ok := am[id]; !ok {
			added = append(added, id)
		} else if old.ContentDigest != n.ContentDigest {
			changed = append(changed, id)
		}
	}
	for id := range am {
		if _, ok := bm[id]; !ok {
			removed = append(removed, id)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	sort.Strings(changed)
	return
}
