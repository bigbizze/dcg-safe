package cli

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/bigbizze/dcg-safe/internal/install"
)

func TestParseCapturePreservesCommandVector(t *testing.T) {
	parsed, err := parseCapture([]string{
		"--stderr=/tmp/stderr",
		"--stdout", "/tmp/stdout",
		"--status", "/tmp/status",
		"--",
		"command",
		"space value",
		"*",
		"$HOME",
		"--child-option",
	})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.stdoutPath != "/tmp/stdout" || parsed.stderrPath != "/tmp/stderr" ||
		parsed.statusPath != "/tmp/status" {
		t.Fatalf("paths = %+v", parsed)
	}
	want := []string{"command", "space value", "*", "$HOME", "--child-option"}
	if !reflect.DeepEqual(parsed.command, want) {
		t.Fatalf("command = %#v, want %#v", parsed.command, want)
	}
}

func TestParseCaptureRejectsMalformedCLI(t *testing.T) {
	tests := map[string][]string{
		"missing separator": {"--stdout", "/tmp/o", "--stderr", "/tmp/e", "--status", "/tmp/s", "cmd"},
		"missing command":   {"--stdout", "/tmp/o", "--stderr", "/tmp/e", "--status", "/tmp/s", "--"},
		"missing path":      {"--stdout", "--", "cmd"},
		"missing flag":      {"--stdout", "/tmp/o", "--stderr", "/tmp/e", "--", "cmd"},
		"duplicate flag":    {"--stdout", "/tmp/o", "--stdout", "/tmp/o2", "--stderr", "/tmp/e", "--status", "/tmp/s", "--", "cmd"},
		"unknown flag":      {"--output", "/tmp/o", "--", "cmd"},
	}
	for name, arguments := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseCapture(arguments); err == nil {
				t.Fatal("parseCapture unexpectedly succeeded")
			}
		})
	}
}

func TestTopLevelVersionAndHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"--version"}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("version code = %d, stderr=%s", code, stderr.String())
	}
	if stdout.String() != "dcg-safe dev\n" || stderr.Len() != 0 {
		t.Fatalf("version stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	stdout.Reset()
	if code := Run([]string{"--help"}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("help code = %d", code)
	}
	if !strings.Contains(stdout.String(), "dcg-safe capture") {
		t.Fatalf("help = %q", stdout.String())
	}
}

func TestCaptureParseFailureUsesSetupFailureCode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"capture", "--stdout", "/tmp/o"}, strings.NewReader(""), &stdout, &stderr)
	if code != 125 {
		t.Fatalf("code = %d, stderr=%s", code, stderr.String())
	}
}

func TestInternalDelegateInstallJSONPlan(t *testing.T) {
	root := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"internal", "delegate-install",
		"--plan",
		"--target", "codex",
		"--json",
		"--install-root", root,
	}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	var result install.Result
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &result); err != nil {
		t.Fatalf("decode JSON-only stdout: %v\n%s", err, stdout.String())
	}
	if len(result.Targets["tools"].Files) != 1 || len(result.Targets["codex"].Files) != 2 {
		t.Fatalf("targets = %+v", result.Targets)
	}
	for _, target := range result.Targets {
		for _, file := range target.Files {
			if !filepath.IsAbs(file.Path) || file.SHA256 != "" {
				t.Fatalf("invalid planned file: %+v", file)
			}
		}
	}
	if len(result.Notices) != 2 || strings.Contains(stdout.String(), "AGENTS.md") {
		t.Fatalf("unexpected notices/stdout: notices=%#v stdout=%s", result.Notices, stdout.String())
	}
}
