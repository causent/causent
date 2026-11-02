package evalcorpus

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type FreezeRecord struct {
	ManifestCommit string    `yaml:"manifest_commit"`
	FrozenAt       time.Time `yaml:"frozen_at"`
}

func Freeze(repoRoot string) (FreezeRecord, error) {
	corpusRoot := filepath.Join(repoRoot, "evaluation", "corpus")
	manifest := filepath.Join(corpusRoot, "manifest.yaml")
	if _, err := os.Stat(manifest); err != nil {
		return FreezeRecord{}, err
	}
	if dirty, err := corpusDirty(repoRoot); err != nil {
		return FreezeRecord{}, fmt.Errorf("check corpus changes: %w", err)
	} else if dirty {
		return FreezeRecord{}, errors.New("corpus has uncommitted changes; commit it before freezing")
	}
	commit, err := gitOutput(repoRoot, "log", "-1", "--format=%H", "--", "evaluation/corpus/manifest.yaml")
	if err != nil || commit == "" {
		return FreezeRecord{}, errors.New("manifest.yaml is not committed")
	}
	record := FreezeRecord{ManifestCommit: commit, FrozenAt: time.Now().UTC()}
	results := filepath.Join(repoRoot, "evaluation", "results")
	if err := os.MkdirAll(results, 0o755); err != nil {
		return FreezeRecord{}, err
	}
	data, err := yaml.Marshal(record)
	if err != nil {
		return FreezeRecord{}, err
	}
	if err := os.WriteFile(filepath.Join(results, "freeze.yaml"), data, 0o644); err != nil {
		return FreezeRecord{}, err
	}
	return record, nil
}

func CheckFreeze(repoRoot string) error {
	path := filepath.Join(repoRoot, "evaluation", "results", "freeze.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read freeze record: %w", err)
	}
	var record FreezeRecord
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&record); err != nil {
		return fmt.Errorf("parse freeze record: %w", err)
	}
	if record.ManifestCommit == "" {
		return errors.New("freeze record has no manifest commit")
	}
	if dirty, err := corpusDirtySince(repoRoot, record.ManifestCommit); err != nil {
		return fmt.Errorf("check corpus against freeze: %w", err)
	} else if dirty {
		return errors.New("corpus changed since the recorded freeze commit")
	}
	return nil
}

func corpusDirty(repoRoot string) (bool, error) {
	output, err := gitOutput(repoRoot, "status", "--porcelain", "--", "evaluation/corpus")
	return output != "", err
}

func corpusDirtySince(repoRoot, commit string) (bool, error) {
	output, err := gitOutput(repoRoot, "diff", "--name-only", commit, "--", "evaluation/corpus")
	if err != nil {
		return false, err
	}
	if output != "" {
		return true, nil
	}
	return corpusDirty(repoRoot)
}

func gitOutput(repoRoot string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", repoRoot}, args...)...)
	output, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(output)), err
}
