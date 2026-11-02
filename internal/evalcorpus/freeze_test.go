package evalcorpus

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestFreezeRejectsCorpusChanges(t *testing.T) {
	root := t.TempDir()
	corpus := filepath.Join(root, "evaluation", "corpus", "cases", "case")
	if err := os.MkdirAll(corpus, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, "evaluation", "corpus", "manifest.yaml"), "version: '1'\ncases:\n  - id: case\n    tier: log_only\n    category: regression\n")
	write(filepath.Join(corpus, "metadata.yaml"), "id: case\ntier: log_only\ncategory: regression\nrepo: repo\nrun_url: run\nlog_sha256: abc\nlicense_note: test\nredacted: true\n")
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, output)
		}
	}
	git("init", "-q")
	git("config", "user.email", "test@example.com")
	git("config", "user.name", "eval test")
	git("add", "evaluation/corpus")
	git("commit", "-qm", "freeze corpus")
	if _, err := Freeze(root); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(corpus, "metadata.yaml"), "id: case\ntier: log_only\ncategory: regression\nrepo: changed\nrun_url: run\nlog_sha256: abc\nlicense_note: test\nredacted: true\n")
	if err := CheckFreeze(root); err == nil {
		t.Fatal("expected freeze check to reject modified corpus")
	}
}
