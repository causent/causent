package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Detection is deliberately evidence based: a finding always records the file
// or workflow line that caused it to be reported.
type Finding struct{ Name, Evidence string }
type RepositoryDetection struct {
	Root                                                                                         string
	Languages, BuildSystems, PackageManagers, Manifests, CIProviders, Workflows, RuntimeVersions []Finding
	TestCommands                                                                                 []Finding
}

type ProjectDetector interface {
	Detect(string) (RepositoryDetection, error)
}
type detector struct{}

func (detector) Detect(root string) (RepositoryDetection, error) {
	var d RepositoryDetection
	d.Root = root
	add := func(dst *[]Finding, name, evidence string) {
		for i := range *dst {
			if (*dst)[i].Name == name {
				if evidence != "" && !strings.Contains((*dst)[i].Evidence, evidence) {
					(*dst)[i].Evidence += ", " + evidence
				}
				return
			}
		}
		*dst = append(*dst, Finding{name, evidence})
	}
	exists := func(name string) bool { _, err := os.Stat(filepath.Join(root, name)); return err == nil }
	if exists("go.mod") {
		add(&d.Languages, "Go", "go.mod")
		add(&d.BuildSystems, "go", "go.mod")
		add(&d.Manifests, "go.mod", "go.mod")
		if v := fileLine(root, "go.mod", `^go\s+(.+)$`); v != "" {
			add(&d.RuntimeVersions, "Go "+v, "go.mod")
		}
	}
	if exists("package.json") {
		add(&d.Languages, "Node.js", "package.json")
		add(&d.Manifests, "package.json", "package.json")
		for _, n := range []string{"package-lock.json", "npm-shrinkwrap.json"} {
			if exists(n) {
				add(&d.PackageManagers, "npm", n)
			}
		}
		if exists("yarn.lock") {
			add(&d.PackageManagers, "Yarn", "yarn.lock")
		}
		if exists("pnpm-lock.yaml") {
			add(&d.PackageManagers, "pnpm", "pnpm-lock.yaml")
		}
		if exists("package-lock.json") {
			add(&d.PackageManagers, "npm", "package-lock.json")
		}
		if cmd := packageScript(root, "test"); cmd != "" {
			add(&d.TestCommands, cmd, "package.json scripts.test")
		}
	}
	if exists("pyproject.toml") {
		add(&d.Languages, "Python", "pyproject.toml")
		add(&d.Manifests, "pyproject.toml", "pyproject.toml")
	}
	if exists("requirements.txt") {
		add(&d.Languages, "Python", "requirements.txt")
		add(&d.Manifests, "requirements.txt", "requirements.txt")
		add(&d.PackageManagers, "pip", "requirements.txt")
	}
	if exists("Cargo.toml") {
		add(&d.Languages, "Rust", "Cargo.toml")
		add(&d.BuildSystems, "Cargo", "Cargo.toml")
		add(&d.Manifests, "Cargo.toml", "Cargo.toml")
	}
	for _, n := range []string{"MODULE.bazel", "WORKSPACE", ".bazelversion"} {
		if exists(n) {
			add(&d.BuildSystems, "Bazel", n)
			add(&d.Manifests, n, n)
		}
	}
	if exists(".github") {
		entries, _ := os.ReadDir(filepath.Join(root, ".github", "workflows"))
		for _, e := range entries {
			if !e.IsDir() && (strings.HasSuffix(e.Name(), ".yml") || strings.HasSuffix(e.Name(), ".yaml")) {
				name := e.Name()
				workflowPath := filepath.Join(root, ".github", "workflows", name)
				workflowName := fileLine(workflowPath, "", `^name:\s*["']?([^"']+?)["']?$`)
				if workflowName == "" {
					workflowName = strings.TrimSuffix(strings.TrimSuffix(name, ".yml"), ".yaml")
				}
				add(&d.CIProviders, "GitHub Actions", filepath.Join(".github/workflows", name))
				add(&d.Workflows, workflowName, filepath.Join(".github/workflows", name))
				for _, line := range workflowLines(workflowPath) {
					if strings.Contains(strings.TrimSpace(line), "run:") {
						cmd := strings.TrimSpace(strings.TrimSpace(strings.SplitN(line, "run:", 2)[1]))
						if isTestCommand(cmd) {
							add(&d.TestCommands, cmd, filepath.Join(".github/workflows", name))
						}
					}
				}
			}
		}
	}
	for _, a := range [][]Finding{d.Languages, d.BuildSystems, d.PackageManagers, d.Manifests, d.CIProviders, d.Workflows, d.RuntimeVersions, d.TestCommands} {
		sort.Slice(a, func(i, j int) bool { return a[i].Name < a[j].Name })
	}
	return d, nil
}

func fileLine(root, name, pattern string) string {
	re := regexp.MustCompile(pattern)
	path := root
	if name != "" {
		path = filepath.Join(root, name)
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		if m := re.FindStringSubmatch(strings.TrimSpace(s.Text())); len(m) > 1 {
			return m[1]
		}
	}
	return ""
}
func workflowLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		out = append(out, s.Text())
	}
	return out
}
func packageScript(root, key string) string {
	b, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil {
		return ""
	}
	re := regexp.MustCompile(`"` + key + `"\s*:\s*"([^"]+)"`)
	m := re.FindSubmatch(b)
	if len(m) == 2 {
		return "npm " + key
	}
	return ""
}
func isTestCommand(s string) bool {
	s = strings.TrimSpace(s)
	return strings.Contains(s, "go test") || strings.Contains(s, "npm test") || strings.Contains(s, "yarn test") || strings.Contains(s, "pnpm test") || strings.Contains(s, "pytest") || strings.Contains(s, "cargo test") || strings.Contains(s, "bazel test")
}

func renderInitConfig(d RepositoryDetection) string {
	cmd := ""
	if len(d.TestCommands) > 0 {
		cmd = d.TestCommands[0].Name
	}
	return fmt.Sprintf("# Generated by causent init. Review command before committing.\ncommand: %q\n", cmd)
}
func renderInitWorkflow(d RepositoryDetection) string {
	names := []string{}
	for _, f := range d.Workflows {
		if !strings.EqualFold(f.Name, "Causent") && f.Name != "causent.yml" {
			names = append(names, strings.TrimSuffix(strings.TrimSuffix(f.Name, ".yml"), ".yaml"))
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return "name: Causent\n\non:\n  workflow_dispatch:\n\npermissions:\n  actions: read\n  contents: read\n  issues: write\n  pull-requests: write\n\njobs:\n  diagnose:\n    uses: causent/causent/.github/workflows/ci-diagnose.yml@v1\n"
	}
	return fmt.Sprintf("name: Causent\n\non:\n  workflow_run:\n    workflows: [%s]\n    types: [completed]\n\npermissions:\n  actions: read\n  contents: read\n  issues: write\n  pull-requests: write\n\njobs:\n  diagnose:\n    if: github.event.workflow_run.conclusion == 'failure' && github.event.workflow_run.head_repository.full_name == github.repository\n    uses: causent/causent/.github/workflows/ci-diagnose.yml@v1\n    with:\n      run_id: ${{ github.event.workflow_run.id }}\n      head_sha: ${{ github.event.workflow_run.head_sha }}\n      base_sha: ${{ github.event.workflow_run.pull_requests[0].base.sha }}\n", strings.Join(names, ", "))
}

func runInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	repo := fs.String("repo", ".", "repository path")
	yes := fs.Bool("yes", false, "write proposed files without prompting")
	fs.Parse(args)
	root, err := filepath.Abs(*repo)
	if err != nil {
		fatalInit(err)
	}
	d, err := (detector{}).Detect(root)
	if err != nil {
		fatalInit(err)
	}
	fmt.Println("Causent repository setup")
	fmt.Printf("Repository: %s\n\n", root)
	fmt.Println("Detected")
	printFindings("Languages", d.Languages)
	printFindings("Build systems", d.BuildSystems)
	printFindings("Package managers", d.PackageManagers)
	printFindings("CI providers", d.CIProviders)
	printFindings("Workflows", d.Workflows)
	printFindings("Runtime versions", d.RuntimeVersions)
	if len(d.TestCommands) > 0 {
		printFindings("Test commands", d.TestCommands)
	} else {
		fmt.Println("Test commands: none confirmed")
		fmt.Println("  Evidence checked: package scripts and GitHub Actions run steps")
		fmt.Println("  Action required: set the exact failing CI command in .causent.yml")
	}
	fmt.Println()
	fmt.Println("Proposed files")
	fmt.Println("  .causent.yml")
	fmt.Println("  .github/workflows/causent.yml")
	if len(d.TestCommands) > 1 {
		fmt.Println("\nMore than one test command was detected. The first one will be proposed; review it before committing.")
	}
	if len(d.TestCommands) == 0 {
		fmt.Println("\nThe configuration will contain an empty command because no safe test command was confirmed.")
	}
	files := map[string]string{".causent.yml": renderInitConfig(d), filepath.Join(".github", "workflows", "causent.yml"): renderInitWorkflow(d)}
	for name := range files {
		path := filepath.Join(root, name)
		if _, e := os.Stat(path); e == nil && !*yes {
			fmt.Printf("%s exists; overwrite? [y/N] ", name)
			answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			if strings.ToLower(strings.TrimSpace(answer)) != "y" {
				fmt.Println("  skipped " + name)
				delete(files, name)
			}
		}
	}
	for name, content := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			fatalInit(err)
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			fatalInit(err)
		}
		fmt.Println("  wrote " + name)
	}
	fmt.Println("\nNext steps")
	fmt.Println("  1. Review .causent.yml and confirm command matches CI.")
	fmt.Println("  2. Review .github/workflows/causent.yml and the workflow name it watches.")
	fmt.Println("  3. Commit both files and push a test change.")
	fmt.Println("  4. Run causent diagnose locally before relying on CI comments.")
}
func printFindings(label string, fs []Finding) {
	if len(fs) == 0 {
		return
	}
	fmt.Printf("  %s:\n", label)
	for _, f := range fs {
		if f.Evidence == "" {
			fmt.Printf("    - %s\n", f.Name)
		} else {
			fmt.Printf("    - %s\n      evidence: %s\n", f.Name, f.Evidence)
		}
	}
}
func fatalInit(err error) { fmt.Fprintln(os.Stderr, "causent init: "+err.Error()); os.Exit(1) }
