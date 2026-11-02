package evalcorpus

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

var shaPattern = regexp.MustCompile(`^[0-9a-fA-F]{40,64}$`)

func Load(root string) (Manifest, []Case, error) {
	manifest, err := loadYAML[Manifest](filepath.Join(root, "manifest.yaml"))
	if err != nil {
		return Manifest{}, nil, err
	}
	if err := validateManifest(manifest); err != nil {
		return Manifest{}, nil, err
	}
	cases := make([]Case, 0, len(manifest.Cases))
	for _, entry := range manifest.Cases {
		dir := filepath.Join(root, "cases", entry.ID)
		metadata, err := loadYAML[Metadata](filepath.Join(dir, "metadata.yaml"))
		if err != nil {
			return Manifest{}, nil, fmt.Errorf("case %s metadata: %w", entry.ID, err)
		}
		if err := ValidateMetadata(metadata); err != nil {
			return Manifest{}, nil, fmt.Errorf("case %s metadata: %w", entry.ID, err)
		}
		if metadata.ID != entry.ID || metadata.Tier != entry.Tier || metadata.Category != entry.Category {
			return Manifest{}, nil, fmt.Errorf("case %s metadata does not match manifest", entry.ID)
		}
		log, err := readFailureLog(dir, metadata)
		if err != nil {
			return Manifest{}, nil, fmt.Errorf("case %s failure log: %w", entry.ID, err)
		}
		cases = append(cases, Case{Dir: dir, Metadata: metadata, Input: RunnerInput{FailureLog: log, Metadata: metadata}})
	}
	return manifest, cases, nil
}

func ValidateMetadata(m Metadata) error {
	if m.ID == "" || m.Repo == "" || m.RunURL == "" || m.LogSHA256 == "" || m.LicenseNote == "" {
		return errors.New("id, repo, run_url, log_sha256, and license_note are required")
	}
	if !validTier(m.Tier) || !validCategory(m.Category) {
		return fmt.Errorf("invalid tier or category")
	}
	if !shaPattern.MatchString(m.LogSHA256) {
		return fmt.Errorf("log_sha256 must be a hexadecimal digest")
	}
	if m.Tier == TierFull && (m.HeadSHA == "" || m.BaseSHA == "" || len(m.Command) == 0) {
		return errors.New("full cases require head_sha, base_sha, and command")
	}
	if m.Tier == TierLogOnly && (m.BaseSHA != "" || m.HeadSHA != "" || len(m.Command) > 0) {
		return errors.New("log_only cases must not contain full-tier revision or command fields")
	}
	return nil
}

func ValidateExpected(e Expected) error {
	if e.PrimaryFailure == "" || e.EvidenceSource == "" || e.Annotator == "" {
		return errors.New("primary_failure, evidence_source, and annotator are required")
	}
	if !validCategory(e.Category) || (e.ExpectedOutcome != OutcomeAnswerable && e.ExpectedOutcome != OutcomeInsufficientEvidence) {
		return errors.New("invalid expected category or outcome")
	}
	return nil
}

func loadExpected(path string) (Expected, error) {
	expected, err := loadYAML[Expected](path)
	if err != nil {
		return Expected{}, err
	}
	return expected, ValidateExpected(expected)
}

func loadYAML[T any](path string) (T, error) {
	var value T
	data, err := os.ReadFile(path)
	if err != nil {
		return value, err
	}
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&value); err != nil {
		return value, err
	}
	return value, nil
}

func readFailureLog(dir string, metadata Metadata) (string, error) {
	path := filepath.Join(dir, "failure.log")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) && metadata.LogCachePath != "" {
		data, err = os.ReadFile(metadata.LogCachePath)
	}
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), metadata.LogSHA256) {
		return "", errors.New("log_sha256 does not match failure log")
	}
	return string(data), nil
}

func validateManifest(m Manifest) error {
	if m.Version == "" || len(m.Cases) == 0 {
		return errors.New("manifest version and cases are required")
	}
	seen := map[string]bool{}
	for _, c := range m.Cases {
		if c.ID == "" || seen[c.ID] || !validTier(c.Tier) || !validCategory(c.Category) {
			return fmt.Errorf("invalid or duplicate manifest case %q", c.ID)
		}
		seen[c.ID] = true
	}
	return nil
}

func validTier(t Tier) bool { return t == TierLogOnly || t == TierFull }

func validCategory(c Category) bool {
	switch c {
	case CategoryPreExisting, CategoryRegression, CategoryDependency, CategoryFlaky, CategoryInfrastructure, CategoryNotReproduced:
		return true
	default:
		return false
	}
}
