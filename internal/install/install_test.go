package install

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestTargetMappings(t *testing.T) {
	root := t.TempDir()
	tests := []struct {
		target      string
		want        map[string]int
		noticeCount int
	}{
		{target: "tools", want: map[string]int{"tools": 1}, noticeCount: 1},
		{target: "codex", want: map[string]int{"tools": 1, "codex": 2}, noticeCount: 2},
		{target: "claude", want: map[string]int{"tools": 1, "claude": 2}, noticeCount: 1},
		{target: "all", want: map[string]int{"tools": 1, "codex": 2, "claude": 2}, noticeCount: 2},
	}
	for _, test := range tests {
		t.Run(test.target, func(t *testing.T) {
			result, err := Execute(Options{
				Operation:   "plan",
				Target:      test.target,
				InstallRoot: root,
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Targets) != len(test.want) {
				t.Fatalf("targets = %+v, want %+v", result.Targets, test.want)
			}
			for target, count := range test.want {
				files := result.Targets[target].Files
				if len(files) != count {
					t.Fatalf("%s files = %d, want %d", target, len(files), count)
				}
				for _, file := range files {
					if !filepath.IsAbs(file.Path) || file.SHA256 != "" {
						t.Fatalf("invalid plan file: %+v", file)
					}
					if !pathWithin(file.Path, root) {
						t.Fatalf("planned path escaped root: %s", file.Path)
					}
				}
			}
			if len(result.Notices) != test.noticeCount {
				t.Fatalf("notices = %#v", result.Notices)
			}
			if len(result.Notices) == 0 || result.Notices[0] != policyNotice {
				t.Fatalf("policy notice = %#v", result.Notices)
			}
			if test.target == "codex" || test.target == "all" {
				if result.Notices[1] != codexNotice {
					t.Fatalf("codex notice = %#v", result.Notices)
				}
			}
		})
	}
	if _, err := os.Stat(filepath.Join(root, ".local")); !os.IsNotExist(err) {
		t.Fatalf("plans wrote staging files: %v", err)
	}
}

func TestInstallIsAtomicExactModeAndHasVerifiableHashes(t *testing.T) {
	root := t.TempDir()
	executable := filepath.Join(root, "source-dcg-safe")
	executableBody := []byte("new executable bytes")
	if err := os.WriteFile(executable, executableBody, 0o755); err != nil {
		t.Fatal(err)
	}
	toolPath := filepath.Join(root, ".local", "bin", "dcg-safe")
	if err := os.MkdirAll(filepath.Dir(toolPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(toolPath, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	oldMask := setInstallUmask(0o777)
	t.Cleanup(func() { setInstallUmask(oldMask) })
	result, err := Execute(Options{
		Operation:   "install",
		Target:      "all",
		InstallRoot: root,
		Executable:  executable,
	})
	setInstallUmask(oldMask)
	if err != nil {
		t.Fatal(err)
	}
	for target, targetResult := range result.Targets {
		for _, file := range targetResult.Files {
			body, err := os.ReadFile(file.Path)
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(body)
			if file.SHA256 != hex.EncodeToString(sum[:]) {
				t.Fatalf("%s hash = %s, recomputed %x", file.Path, file.SHA256, sum)
			}
			info, err := os.Stat(file.Path)
			if err != nil {
				t.Fatal(err)
			}
			wantMode := os.FileMode(0o644)
			if target == "tools" {
				wantMode = 0o755
				if !bytes.Equal(body, executableBody) {
					t.Fatalf("installed executable = %q", body)
				}
			}
			if info.Mode().Perm() != wantMode {
				t.Fatalf("%s mode = %04o, want %04o", file.Path, info.Mode().Perm(), wantMode)
			}
		}
	}
	entries, err := os.ReadDir(filepath.Dir(toolPath))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "dcg-safe" {
		t.Fatalf("atomic install left temporary files: %+v", entries)
	}
}

func TestEmbeddedPayloadBytesAreInstalled(t *testing.T) {
	root := t.TempDir()
	executable := filepath.Join(root, "source")
	if err := os.WriteFile(executable, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	result, err := Execute(Options{
		Operation:   "install",
		Target:      "codex",
		InstallRoot: root,
		Executable:  executable,
	})
	if err != nil {
		t.Fatal(err)
	}
	files := result.Targets["codex"].Files
	if len(files) != 2 {
		t.Fatalf("codex files = %+v", files)
	}
	for _, file := range files {
		body, err := os.ReadFile(file.Path)
		if err != nil {
			t.Fatal(err)
		}
		switch filepath.Base(file.Path) {
		case "SKILL.md":
			if !strings.Contains(string(body), "name: dcg-safe") {
				t.Fatalf("unexpected skill payload:\n%s", body)
			}
		case "openai.yaml":
			if !strings.Contains(string(body), `display_name: "dcg-safe"`) {
				t.Fatalf("unexpected metadata payload:\n%s", body)
			}
		default:
			t.Fatalf("unexpected Codex payload: %s", file.Path)
		}
	}
}

func TestHostUninstallAlsoRemovesSharedExecutable(t *testing.T) {
	for _, target := range []string{"codex", "claude"} {
		t.Run(target, func(t *testing.T) {
			root := t.TempDir()
			executable := filepath.Join(root, "source")
			if err := os.WriteFile(executable, []byte("binary"), 0o755); err != nil {
				t.Fatal(err)
			}
			installed, err := Execute(Options{
				Operation:   "install",
				Target:      target,
				InstallRoot: root,
				Executable:  executable,
			})
			if err != nil {
				t.Fatal(err)
			}
			removed, err := Execute(Options{
				Operation:   "uninstall",
				Target:      target,
				InstallRoot: root,
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(removed.Notices) != 0 {
				t.Fatalf("uninstall notices = %#v", removed.Notices)
			}
			for _, targetResult := range installed.Targets {
				for _, file := range targetResult.Files {
					if _, err := os.Lstat(file.Path); !os.IsNotExist(err) {
						t.Fatalf("%s survived host uninstall: %v", file.Path, err)
					}
				}
			}
		})
	}
}

func TestOperationParsingAndJSONOnlyOutput(t *testing.T) {
	root := t.TempDir()
	executable := filepath.Join(root, "source")
	if err := os.WriteFile(executable, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		args []string
		code int
	}{
		{
			name: "conflicting operations",
			args: []string{"--plan", "--install", "--target", "tools", "--json", "--install-root", root},
			code: 2,
		},
		{
			name: "relative root",
			args: []string{"--plan", "--target", "tools", "--json", "--install-root", "relative"},
			code: 1,
		},
		{
			name: "nonnormal root",
			args: []string{"--plan", "--target", "tools", "--json", "--install-root", root + "/../escape"},
			code: 1,
		},
		{
			name: "unknown target",
			args: []string{"--plan", "--target", "other", "--json", "--install-root", root},
			code: 1,
		},
		{
			name: "default install",
			args: []string{"--target", "tools", "--json", "--install-root", root},
			code: 0,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(test.args, &stdout, &stderr, executable)
			if code != test.code {
				t.Fatalf("code = %d, want %d; stdout=%s stderr=%s", code, test.code, stdout.String(), stderr.String())
			}
			if code != 0 {
				if stdout.Len() != 0 {
					t.Fatalf("error wrote stdout: %s", stdout.String())
				}
				return
			}
			var result Result
			if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &result); err != nil {
				t.Fatalf("stdout is not JSON-only: %v\n%s", err, stdout.String())
			}
			if result.Operation != "install" || result.Schema != 1 || result.Kind != "delegated" {
				t.Fatalf("result = %+v", result)
			}
		})
	}
}

func TestDocumentedInstallerCommandsAgainstTemporaryHome(t *testing.T) {
	repository := filepath.Clean(filepath.Join("..", ".."))
	releaseDir := t.TempDir()
	binary := filepath.Join(releaseDir, "dcg-safe")
	build := exec.Command("go", "build", "-o", binary, "./cmd/dcg-safe")
	build.Dir = repository
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build release binary: %v\n%s", err, output)
	}
	scriptBody, err := os.ReadFile(filepath.Join(repository, "install-skill.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(releaseDir, "install-skill.sh")
	if err := os.WriteFile(script, scriptBody, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(script, 0o755); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(t.TempDir(), "home")
	if err := os.Mkdir(stage, 0o700); err != nil {
		t.Fatal(err)
	}

	plan := runInstallerJSON(t, script, "--plan", "--target", "all", "--json", "--install-root", stage)
	installed := runInstallerJSON(t, script, "--install", "--target", "all", "--json", "--install-root", stage)
	if strings.Join(resultPaths(plan), "\n") != strings.Join(resultPaths(installed), "\n") {
		t.Fatalf("planned paths differ from staged paths:\nplan=%v\ninstall=%v", resultPaths(plan), resultPaths(installed))
	}
	for _, target := range installed.Targets {
		for _, file := range target.Files {
			if file.SHA256 == "" {
				t.Fatalf("installed file lacks hash: %+v", file)
			}
			body, err := os.ReadFile(file.Path)
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(body)
			if file.SHA256 != hex.EncodeToString(sum[:]) {
				t.Fatalf("reported hash mismatch for %s", file.Path)
			}
		}
	}

	uninstalled := runInstallerJSON(t, script, "--uninstall", "--target", "all", "--json", "--install-root", stage)
	for _, path := range resultPaths(uninstalled) {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("uninstall left %s: %v", path, err)
		}
	}
	defaultInstall := runInstallerJSON(t, script, "--target", "tools", "--json", "--install-root", stage)
	if defaultInstall.Operation != "install" || len(defaultInstall.Targets) != 1 ||
		len(defaultInstall.Targets["tools"].Files) != 1 {
		t.Fatalf("default operation result = %+v", defaultInstall)
	}
}

func runInstallerJSON(t *testing.T, script string, arguments ...string) Result {
	t.Helper()
	command := exec.Command(script, arguments...)
	command.Dir = t.TempDir()
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("%s %v: %v\nstdout=%s\nstderr=%s", script, arguments, err, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("JSON installer wrote stderr: %s", stderr.String())
	}
	var result Result
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &result); err != nil {
		t.Fatalf("decode installer JSON: %v\n%s", err, stdout.String())
	}
	return result
}

func resultPaths(result Result) []string {
	var paths []string
	for _, target := range result.Targets {
		for _, file := range target.Files {
			paths = append(paths, file.Path)
		}
	}
	sort.Strings(paths)
	return paths
}

var setInstallUmask = func(mask int) int {
	return installUmask(mask)
}

var installUmask = func(mask int) int {
	panic("install umask implementation missing")
}
