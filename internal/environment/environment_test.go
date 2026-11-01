package environment

import (
	"os"
	"path/filepath"
	"testing"
)

func writeEnvFixture(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestRegistryDetectsInitialAdapters(t *testing.T) {
	cases := []struct {
		name    string
		files   map[string]string
		adapter string
	}{
		{"go", map[string]string{"go.mod": "module x\ngo 1.26\n"}, "go"},
		{"node", map[string]string{"package.json": "{\"scripts\":{\"test\":\"vitest\"}}", "pnpm-lock.yaml": "lockfileVersion: 9"}, "node"},
		{"python", map[string]string{"pyproject.toml": "[project]\nname='x'\n", "requirements.txt": "pytest"}, "python"},
		{"rust", map[string]string{"Cargo.toml": "[package]\nname='x'\n"}, "rust"},
		{"bazel", map[string]string{"MODULE.bazel": "module(name='x')\n", ".bazelversion": "7.1.0\n"}, "bazel"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := writeEnvFixture(t, tc.files)
			got, err := NewRegistry().Detect(root)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || got[0].Name != tc.adapter {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

func TestCommandSelectionPrecedence(t *testing.T) {
	root := writeEnvFixture(t, map[string]string{"go.mod": "module x\n"})
	r := NewRegistry()
	if got, source, err := r.SelectTestCommand(root, Command{"custom"}, nil); err != nil || source != "configuration" || got[0] != "custom" {
		t.Fatalf("explicit: %v %s %v", got, source, err)
	}
	if _, source, err := r.SelectTestCommand(root, nil, Command{"ci"}); err != nil || source != "ci" {
		t.Fatalf("ci: %s %v", source, err)
	}
	if got, source, err := r.SelectTestCommand(root, nil, nil); err != nil || source != "adapter" || got[0] != "go" {
		t.Fatalf("adapter: %v %s %v", got, source, err)
	}
}

func TestBazelDoesNotInventTestCommand(t *testing.T) {
	root := writeEnvFixture(t, map[string]string{"MODULE.bazel": "module(name='x')"})
	if _, ok := (BazelAdapter{}).DiscoverTestCommand(root); ok {
		t.Fatal("bazel adapter invented a command")
	}
}
