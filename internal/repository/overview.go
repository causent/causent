package repository

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Overview is a cheap structural summary of a repository revision.
// It is intentionally incomplete and must never be treated as an exhaustive graph.
type Overview struct {
	RepositoryID   string            `json:"repository_id"`
	RevisionID     string            `json:"revision_id"`
	CommitSHA      string            `json:"commit_sha"`
	Languages      []string          `json:"languages"`
	BuildSystems   []string          `json:"build_systems"`
	TestFrameworks []string          `json:"test_frameworks"`
	Manifests      []string          `json:"manifests"`
	TopLevelDirs   []string          `json:"top_level_dirs"`
	FileCounts     map[string]int    `json:"file_counts"`
	TestDirs       []string          `json:"test_dirs,omitempty"`
	CoverageNotes  []string          `json:"coverage_notes,omitempty"`
	GeneratedAt    time.Time         `json:"generated_at"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// BuildOverview walks only directory metadata and known manifests.
// It does not parse symbols or relationships.
func BuildOverview(ctx context.Context, root, repositoryID, revisionID, commitSHA string) (Overview, error) {
	ov := Overview{
		RepositoryID: repositoryID,
		RevisionID:   revisionID,
		CommitSHA:    commitSHA,
		FileCounts:   map[string]int{},
		GeneratedAt:  time.Now().UTC(),
		CoverageNotes: []string{
			"overview is structural only; symbol and call relationships require a repository snapshot",
			"missing overview fields must not be interpreted as proof that a language or framework is absent",
		},
	}
	if root == "" {
		return ov, os.ErrInvalid
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return ov, err
	}
	langSet := map[string]bool{}
	buildSet := map[string]bool{}
	testSet := map[string]bool{}
	manifestSet := map[string]bool{}
	var topDirs, testDirs []string

	for _, entry := range entries {
		if ctx.Err() != nil {
			return ov, ctx.Err()
		}
		name := entry.Name()
		if entry.IsDir() {
			if excludedDir(name) {
				continue
			}
			topDirs = append(topDirs, name)
			lower := strings.ToLower(name)
			if lower == "test" || lower == "tests" || strings.HasSuffix(lower, "_test") || lower == "__tests__" {
				testDirs = append(testDirs, name)
			}
			continue
		}
		detectManifest(name, &ov, langSet, buildSet, testSet, manifestSet)
	}

	// Bounded shallow walk for language/file counts without reading file bodies.
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
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
		ext := filepath.Ext(entry.Name())
		if lang := language(ext); lang != "" {
			langSet[lang] = true
			ov.FileCounts[lang]++
		}
		base := entry.Name()
		detectManifest(base, &ov, langSet, buildSet, testSet, manifestSet)
		rel, relErr := filepath.Rel(root, path)
		if relErr == nil {
			parts := strings.Split(rel, string(os.PathSeparator))
			if len(parts) > 1 {
				dir := parts[0]
				lower := strings.ToLower(dir)
				if lower == "test" || lower == "tests" || lower == "__tests__" {
					testDirs = appendUnique(testDirs, dir)
				}
			}
		}
		return nil
	})
	if err != nil {
		return ov, err
	}

	ov.Languages = sortedKeys(langSet)
	ov.BuildSystems = sortedKeys(buildSet)
	ov.TestFrameworks = sortedKeys(testSet)
	ov.Manifests = sortedKeys(manifestSet)
	sort.Strings(topDirs)
	ov.TopLevelDirs = topDirs
	sort.Strings(testDirs)
	ov.TestDirs = testDirs
	return ov, nil
}

func detectManifest(name string, ov *Overview, lang, build, test, manifest map[string]bool) {
	switch name {
	case "go.mod", "go.sum":
		lang["go"] = true
		build["go"] = true
		manifest[name] = true
	case "Cargo.toml", "Cargo.lock":
		lang["rust"] = true
		build["cargo"] = true
		manifest[name] = true
	case "package.json", "pnpm-lock.yaml", "yarn.lock", "package-lock.json":
		lang["javascript"] = true
		build["npm"] = true
		manifest[name] = true
	case "pyproject.toml", "requirements.txt", "setup.py", "Pipfile":
		lang["python"] = true
		build["python"] = true
		manifest[name] = true
	case "pom.xml", "build.gradle", "build.gradle.kts":
		build["jvm"] = true
		manifest[name] = true
	case "Makefile", "CMakeLists.txt", "BUILD", "BUILD.bazel", "WORKSPACE", "meson.build":
		build[strings.ToLower(name)] = true
		manifest[name] = true
	case "pytest.ini", "tox.ini", "conftest.py":
		test["pytest"] = true
		manifest[name] = true
	case "jest.config.js", "jest.config.ts", "vitest.config.ts":
		test["jest/vitest"] = true
		manifest[name] = true
	}
	_ = ov
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
