// Package repository builds a bounded, revision-aware repository/program graph.
// It uses syntax-shaped extraction rather than pretending to be a compiler.
package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/causent/malenia/internal/domain"
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

// AnalyzePaths builds a focused snapshot for evidence-selected files. It is
// used before broad indexing so a large repository cannot starve the actual
// investigation. Relationships are complete for the selected files, not for
// the whole repository; callers must preserve that coverage limitation.
func (a Analyzer) AnalyzePaths(ctx context.Context, root, repositoryID, revisionID, commitSHA string, paths []string) (Snapshot, error) {
	if root == "" || repositoryID == "" || revisionID == "" {
		return Snapshot{}, fmt.Errorf("repository root, repository id, and revision id are required")
	}
	if a.MaxFiles <= 0 {
		a.MaxFiles = 80
	}
	if a.MaxBytes <= 0 {
		a.MaxBytes = 2 << 20
	}
	s := Snapshot{RepositoryID: repositoryID, RevisionID: revisionID, CommitSHA: commitSHA}
	contents := map[string]string{}
	seen := map[string]bool{}
	for _, raw := range paths {
		if ctx.Err() != nil {
			return s, ctx.Err()
		}
		rel := filepath.ToSlash(filepath.Clean(raw))
		if rel == "." || rel == ".." || strings.HasPrefix(rel, "../") || filepath.IsAbs(raw) || seen[rel] || language(filepath.Ext(rel)) == "" {
			continue
		}
		seen[rel] = true
		if len(seen) > a.MaxFiles {
			break
		}
		path := filepath.Join(root, filepath.FromSlash(rel))
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if len(data) > a.MaxBytes {
			continue
		}
		text := string(data)
		contents[rel] = text
		lang := language(filepath.Ext(rel))
		digest := sha256.Sum256(data)
		fileID := nodeID(repositoryID, revisionID, "file", rel)
		s.Nodes = append(s.Nodes, domain.ProgramNode{ID: fileID, RepositoryID: repositoryID, RevisionID: revisionID, Type: "File", Name: rel, Identity: lang + ":" + rel, FilePath: rel, Language: lang, StartLine: 1, EndLine: strings.Count(text, "\n") + 1, ContentDigest: hex.EncodeToString(digest[:])})
		a.extractFile(text, rel, lang, fileID, &s)
	}
	a.buildReferences(contents, &s)
	a.buildVerifiedGoCalls(contents, &s)
	return s, nil
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
	a.buildVerifiedGoCalls(contents, &s)
	return s, nil
}

func (a Analyzer) buildVerifiedGoCalls(contents map[string]string, s *Snapshot) {
	nodesByFile := map[string][]domain.ProgramNode{}
	nodesByName := map[string][]domain.ProgramNode{}
	for _, node := range s.Nodes {
		if node.Type == "Function" || node.Type == "Method" || node.Type == "Test" {
			nodesByFile[node.FilePath] = append(nodesByFile[node.FilePath], node)
			nodesByName[node.Name] = append(nodesByName[node.Name], node)
		}
	}
	seen := map[string]bool{}
	for path, data := range contents {
		if filepath.Ext(path) != ".go" {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, data, 0)
		if err != nil {
			continue
		}
		for _, declaration := range file.Decls {
			fn, ok := declaration.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			var sources []domain.ProgramNode
			for _, node := range nodesByFile[path] {
				if node.Name == fn.Name.Name {
					sources = append(sources, node)
				}
			}
			if len(sources) != 1 {
				continue
			}
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				ident, ok := call.Fun.(*ast.Ident)
				if !ok {
					return true
				}
				targets := nodesByName[ident.Name]
				if len(targets) != 1 || targets[0].ID == sources[0].ID {
					return true
				}
				key := sources[0].ID + ":" + targets[0].ID
				if seen[key] {
					return true
				}
				seen[key] = true
				s.Relationships = append(s.Relationships, domain.Relationship{ID: edgeID(sources[0].ID, "CALLS", targets[0].ID), SourceType: sources[0].Type, SourceID: sources[0].ID, TargetType: targets[0].Type, TargetID: targets[0].ID, Type: "CALLS", RevisionID: s.RevisionID, Metadata: map[string]string{"provenance": "verified_static_call", "verification": "Go AST CallExpr with uniquely resolved identifier"}})
				return true
			})
		}
	}
}

func excludedDir(name string) bool {
	switch name {
	case ".git", ".malenia", "vendor", "node_modules", "dist", "build", "target":
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
	provenance := "dependency"
	switch typ {
	case "CALLS", "TESTS":
		provenance = "inferred_caller"
	case "DEFINES":
		provenance = "enclosing_symbol"
	}
	s.Relationships = append(s.Relationships, domain.Relationship{ID: edgeID(source, typ, target), SourceType: sourceType, SourceID: source, TargetType: targetType, TargetID: target, Type: typ, RevisionID: s.RevisionID, Metadata: map[string]string{"provenance": provenance}})
}

var (
	pyFunc   = regexp.MustCompile(`(?m)^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(`)
	pyClass  = regexp.MustCompile(`(?m)^\s*class\s+([A-Za-z_][A-Za-z0-9_]*)\b`)
	jsFunc   = regexp.MustCompile(`(?m)^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(`)
	importRE = regexp.MustCompile(`(?m)^\s*(?:import\s+(?:[^;]+?\s+from\s+)?|from\s+)(["'][^"']+["']|[^\s;]+)`)
)

func (a Analyzer) extractFile(data, rel, lang, fileID string, s *Snapshot) {
	digest := sha256.Sum256([]byte(data))
	contentDigest := hex.EncodeToString(digest[:])
	addSymbol := func(name, typ string, startLine, endLine int) {
		identity := lang + ":" + rel + ":" + typ + ":" + name
		id := nodeID(s.RepositoryID, s.RevisionID, "symbol", identity)
		s.Nodes = append(s.Nodes, domain.ProgramNode{ID: id, RepositoryID: s.RepositoryID, RevisionID: s.RevisionID, Type: typ, Name: name, Identity: identity, FilePath: rel, Language: lang, StartLine: startLine, EndLine: endLine, ContentDigest: contentDigest})
		addEdge(s, fileID, "File", id, typ, "DEFINES")
	}
	switch lang {
	case "go":
		extractGoSymbols(data, rel, fileID, s, addSymbol)
	case "python":
		for _, m := range pyFunc.FindAllStringSubmatchIndex(data, -1) {
			line := lineAt(data, m[0])
			addSymbol(data[m[2]:m[3]], testOr("Function", rel, data[m[2]:m[3]]), line, strings.Count(data, "\n")+1)
		}
		for _, m := range pyClass.FindAllStringSubmatchIndex(data, -1) {
			line := lineAt(data, m[0])
			addSymbol(data[m[2]:m[3]], "Class", line, strings.Count(data, "\n")+1)
		}
	case "javascript":
		for _, m := range jsFunc.FindAllStringSubmatchIndex(data, -1) {
			line := lineAt(data, m[0])
			addSymbol(data[m[2]:m[3]], "Function", line, strings.Count(data, "\n")+1)
		}
	}
	if lang != "go" {
		for _, m := range importRE.FindAllStringSubmatch(data, -1) {
			if len(m) > 1 {
				target := strings.Trim(m[1], "\"'")
				id := nodeID(s.RepositoryID, s.RevisionID, "dependency", lang+":"+target)
				s.Nodes = append(s.Nodes, domain.ProgramNode{ID: id, RepositoryID: s.RepositoryID, RevisionID: s.RevisionID, Type: "Dependency", Name: target, Identity: lang + ":" + target, Language: lang})
				addEdge(s, fileID, "File", id, "Dependency", "IMPORTS")
			}
		}
	}
}

// extractGoSymbols uses the Go parser's token positions. Regexes cannot
// reliably find declaration ends because braces may occur in signatures,
// comments, literals, generic constraints, and nested blocks.
func extractGoSymbols(data, rel, fileID string, s *Snapshot, add func(string, string, int, int)) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, rel, data, parser.ParseComments)
	if err != nil {
		return
	}
	position := func(pos token.Pos) int { return fset.Position(pos).Line }
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			typ := symbolType(rel, d.Name.Name)
			if d.Recv != nil {
				typ = "Method"
				if strings.HasSuffix(rel, "_test.go") && strings.HasPrefix(d.Name.Name, "Test") {
					typ = "Test"
				}
			}
			add(d.Name.Name, typ, position(d.Pos()), position(d.End()))
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch v := spec.(type) {
				case *ast.TypeSpec:
					add(v.Name.Name, "Class", position(v.Pos()), position(v.End()))
				}
			}
		}
	}
	for _, imp := range file.Imports {
		target := strings.Trim(imp.Path.Value, "\"")
		id := nodeID(s.RepositoryID, s.RevisionID, "dependency", "go:"+target)
		s.Nodes = append(s.Nodes, domain.ProgramNode{ID: id, RepositoryID: s.RepositoryID, RevisionID: s.RevisionID, Type: "Dependency", Name: target, Identity: "go:" + target, Language: "go"})
		addEdge(s, fileID, "File", id, "Dependency", "IMPORTS")
	}
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
	byFile := map[string][]domain.ProgramNode{}
	for _, n := range s.Nodes {
		if n.Type == "Function" || n.Type == "Method" || n.Type == "Test" || n.Type == "Class" {
			byName[n.Name] = append(byName[n.Name], n)
			byFile[n.FilePath] = append(byFile[n.FilePath], n)
		}
	}
	seen := map[string]bool{}
	const maxEdges = 20000
	for _, file := range s.Nodes {
		if file.Type != "File" || len(s.Relationships) >= maxEdges {
			continue
		}
		data := contents[file.FilePath]
		for name, targets := range byName {
			if !regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`).MatchString(data) {
				continue
			}
			for _, target := range targets {
				for _, source := range byFile[file.FilePath] {
					if source.Type == "Class" || source.ID == target.ID {
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
					if len(s.Relationships) >= maxEdges {
						break
					}
				}
				if len(s.Relationships) >= maxEdges {
					break
				}
			}
			if len(s.Relationships) >= maxEdges {
				break
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
