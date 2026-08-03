package capture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_DCG_SAFE_HELPER") != "1" {
		return
	}
	separator := -1
	for index, argument := range os.Args {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator < 0 || separator+1 >= len(os.Args) {
		os.Exit(120)
	}
	mode := os.Args[separator+1]
	arguments := os.Args[separator+2:]
	switch mode {
	case "streams":
		stdin, err := io.ReadAll(os.Stdin)
		if err != nil {
			os.Exit(121)
		}
		cwd, err := os.Getwd()
		if err != nil {
			os.Exit(122)
		}
		payload := struct {
			Args        []string          `json:"args"`
			CWD         string            `json:"cwd"`
			Env         string            `json:"env"`
			SelectedEnv map[string]string `json:"selected_env,omitempty"`
			Stdin       string            `json:"stdin"`
		}{
			Args: arguments,
			CWD:  cwd,
			Env:  os.Getenv("DCG_SAFE_TEST_ENV"),
			SelectedEnv: map[string]string{
				"DCG_CONFIG":          os.Getenv("DCG_CONFIG"),
				"DCG_POLICY_OVERRIDE": os.Getenv("DCG_POLICY_OVERRIDE"),
				"DCG_SAFE_TEST_ENV":   os.Getenv("DCG_SAFE_TEST_ENV"),
				"HOME":                os.Getenv("HOME"),
				"KEEP_ME":             os.Getenv("KEEP_ME"),
				"PWD":                 os.Getenv("PWD"),
				"XDG_CONFIG_HOME":     os.Getenv("XDG_CONFIG_HOME"),
			},
			Stdin: string(stdin),
		}
		if err := json.NewEncoder(os.Stdout).Encode(payload); err != nil {
			os.Exit(123)
		}
		_, _ = os.Stderr.Write([]byte{'e', 'r', 'r', 0, '\n'})
		os.Exit(7)
	case "exit":
		code, err := strconv.Atoi(arguments[0])
		if err != nil {
			os.Exit(124)
		}
		os.Exit(code)
	case "block":
		_, _ = fmt.Fprintln(os.Stdout, "ready")
		for {
			time.Sleep(time.Hour)
		}
	case "touch":
		if err := os.WriteFile(arguments[0], []byte("executed"), 0o600); err != nil {
			os.Exit(125)
		}
		os.Exit(0)
	case "fds":
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			os.Exit(126)
		}
		links := map[string]string{}
		for _, entry := range entries {
			path := filepath.Join("/proc/self/fd", entry.Name())
			target, err := os.Readlink(path)
			if err == nil {
				links[entry.Name()] = target
			}
		}
		if err := json.NewEncoder(os.Stdout).Encode(links); err != nil {
			os.Exit(127)
		}
		os.Exit(0)
	default:
		os.Exit(119)
	}
}

func TestExactStreamsArgumentsAndInheritedContext(t *testing.T) {
	allowChildPolicy(t)
	t.Setenv("GO_WANT_DCG_SAFE_HELPER", "1")
	t.Setenv("DCG_SAFE_TEST_ENV", "inherited-value")
	cwd := t.TempDir()
	canonicalCWD, err := filepath.EvalSymlinks(cwd)
	if err != nil {
		t.Fatal(err)
	}
	cwd = canonicalCWD
	t.Chdir(cwd)
	root := trustedCaptureRoot(t)
	paths := evidencePaths(root, "exact")
	arguments := []string{"space value", "$HOME", "*", ";", `quote"inside`}
	var diagnostics bytes.Buffer
	code := Execute(Options{
		StdoutPath: paths[0],
		StderrPath: paths[1],
		StatusPath: paths[2],
		Command:    helperCommand(t, "streams", arguments...),
		Roots:      []string{root},
		UID:        os.Geteuid(),
		Stdin:      strings.NewReader("stdin-body"),
	}, &diagnostics)
	if code != 7 {
		t.Fatalf("code = %d, diagnostics = %s", code, diagnostics.String())
	}
	if diagnostics.Len() != 0 {
		t.Fatalf("unexpected wrapper diagnostics: %s", diagnostics.String())
	}
	var payload struct {
		Args  []string `json:"args"`
		CWD   string   `json:"cwd"`
		Env   string   `json:"env"`
		Stdin string   `json:"stdin"`
	}
	stdout := readFile(t, paths[0])
	if err := json.Unmarshal(stdout, &payload); err != nil {
		t.Fatalf("decode stdout: %v\n%s", err, stdout)
	}
	if strings.Join(payload.Args, "\x00") != strings.Join(arguments, "\x00") {
		t.Fatalf("args = %#v, want %#v", payload.Args, arguments)
	}
	if payload.CWD != cwd || payload.Env != "inherited-value" || payload.Stdin != "stdin-body" {
		t.Fatalf("inherited context = %+v", payload)
	}
	if got := readFile(t, paths[1]); !bytes.Equal(got, []byte{'e', 'r', 'r', 0, '\n'}) {
		t.Fatalf("stderr = %q", got)
	}
	if got := string(readFile(t, paths[2])); got != "7\n" {
		t.Fatalf("status = %q", got)
	}
}

func TestCompletedOutcomes(t *testing.T) {
	allowChildPolicy(t)
	t.Setenv("GO_WANT_DCG_SAFE_HELPER", "1")
	for _, outcome := range []int{0, 1, 42, 255} {
		t.Run(strconv.Itoa(outcome), func(t *testing.T) {
			root := trustedCaptureRoot(t)
			paths := evidencePaths(root, "exit")
			code := Execute(Options{
				StdoutPath: paths[0],
				StderrPath: paths[1],
				StatusPath: paths[2],
				Command:    helperCommand(t, "exit", strconv.Itoa(outcome)),
				Roots:      []string{root},
				UID:        os.Geteuid(),
				Stdin:      strings.NewReader(""),
			}, io.Discard)
			if code != outcome {
				t.Fatalf("code = %d, want %d", code, outcome)
			}
			if got := string(readFile(t, paths[2])); got != strconv.Itoa(outcome)+"\n" {
				t.Fatalf("status = %q", got)
			}
		})
	}
}

func TestInvocationFailureMappingsKeepCaptures(t *testing.T) {
	allowChildPolicy(t)
	t.Setenv("GO_WANT_DCG_SAFE_HELPER", "1")
	container := t.TempDir()
	nonExecutable := filepath.Join(container, "not-executable")
	if err := os.WriteFile(nonExecutable, []byte("#!/bin/sh\nexit 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	badFormat := filepath.Join(container, "bad-format")
	if err := os.WriteFile(badFormat, []byte("not an executable format\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(badFormat, 0o755); err != nil {
		t.Fatal(err)
	}
	missingInterpreter := filepath.Join(container, "missing-interpreter")
	if err := os.WriteFile(missingInterpreter, []byte("#!/definitely/missing/dcg-safe-interpreter\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(missingInterpreter, 0o755); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(container, "directory")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	dotCommand := filepath.Join(container, "dot-command")
	if err := os.WriteFile(dotCommand, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		command []string
		outcome int
		dotPath bool
	}{
		{name: "missing", command: []string{filepath.Join(container, "missing")}, outcome: 127},
		{name: "missing interpreter", command: []string{missingInterpreter}, outcome: 127},
		{name: "permission", command: []string{nonExecutable}, outcome: 126},
		{name: "format", command: []string{badFormat}, outcome: 126},
		{name: "directory", command: []string{directory}, outcome: 126},
		{name: "err dot", command: []string{"dot-command"}, outcome: 126, dotPath: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.dotPath {
				t.Chdir(container)
				t.Setenv("PATH", ".")
			}
			root := trustedCaptureRoot(t)
			paths := evidencePaths(root, strings.ReplaceAll(test.name, " ", "-"))
			var diagnostics bytes.Buffer
			code := Execute(Options{
				StdoutPath: paths[0],
				StderrPath: paths[1],
				StatusPath: paths[2],
				Command:    test.command,
				Roots:      []string{root},
				UID:        os.Geteuid(),
				Stdin:      strings.NewReader(""),
			}, &diagnostics)
			if code != test.outcome {
				t.Fatalf("code = %d, want %d; diagnostics: %s", code, test.outcome, diagnostics.String())
			}
			if diagnostics.Len() == 0 {
				t.Fatal("missing wrapper diagnostic")
			}
			if got := readFile(t, paths[1]); len(got) != 0 {
				t.Fatalf("wrapper diagnostic leaked into child stderr: %q", got)
			}
			if got := string(readFile(t, paths[2])); got != strconv.Itoa(test.outcome)+"\n" {
				t.Fatalf("status = %q", got)
			}
		})
	}
}

func TestOrdinarySetupFailureRollsBackAndNeverExecutes(t *testing.T) {
	allowChildPolicy(t)
	t.Setenv("GO_WANT_DCG_SAFE_HELPER", "1")
	root := trustedCaptureRoot(t)
	paths := evidencePaths(root, "rollback")
	if err := os.WriteFile(paths[1], []byte("preexisting"), 0o600); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(root, "child-ran")
	code := Execute(Options{
		StdoutPath: paths[0],
		StderrPath: paths[1],
		StatusPath: paths[2],
		Command:    helperCommand(t, "touch", sentinel),
		Roots:      []string{root},
		UID:        os.Geteuid(),
		Stdin:      strings.NewReader(""),
	}, io.Discard)
	if code != SetupFailure {
		t.Fatalf("code = %d", code)
	}
	for _, path := range []string{paths[0], paths[2], sentinel} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s exists after rollback: %v", path, err)
		}
	}
	if got := string(readFile(t, paths[1])); got != "preexisting" {
		t.Fatalf("existing target changed: %q", got)
	}
}

func TestHostileUmaskStillProduces0600(t *testing.T) {
	allowChildPolicy(t)
	t.Setenv("GO_WANT_DCG_SAFE_HELPER", "1")
	root := trustedCaptureRoot(t)
	paths := evidencePaths(root, "umask")
	oldMask := unix.Umask(0o777)
	t.Cleanup(func() { unix.Umask(oldMask) })
	code := Execute(Options{
		StdoutPath: paths[0],
		StderrPath: paths[1],
		StatusPath: paths[2],
		Command:    helperCommand(t, "exit", "0"),
		Roots:      []string{root},
		UID:        os.Geteuid(),
		Stdin:      strings.NewReader(""),
	}, io.Discard)
	unix.Umask(oldMask)
	if code != 0 {
		t.Fatalf("code = %d", code)
	}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %04o", path, info.Mode().Perm())
		}
	}
}

func TestPartialStatusWriteIsTruncated(t *testing.T) {
	allowChildPolicy(t)
	t.Setenv("GO_WANT_DCG_SAFE_HELPER", "1")
	root := trustedCaptureRoot(t)
	paths := evidencePaths(root, "partial-status")
	ops := defaultRuntimeOps()
	writes := 0
	ops.status.write = func(fd int, body []byte) (int, error) {
		writes++
		if writes == 1 {
			return unix.Write(fd, body[:1])
		}
		return 0, errors.New("injected status write failure")
	}
	code := execute(Options{
		StdoutPath: paths[0],
		StderrPath: paths[1],
		StatusPath: paths[2],
		Command:    helperCommand(t, "exit", "0"),
		Roots:      []string{root},
		UID:        os.Geteuid(),
		Stdin:      strings.NewReader(""),
	}, io.Discard, ops)
	if code != SetupFailure {
		t.Fatalf("code = %d", code)
	}
	if got := readFile(t, paths[2]); len(got) != 0 {
		t.Fatalf("partial status was not truncated: %q", got)
	}
}

func TestForwardedSignalProducesSignalOutcome(t *testing.T) {
	allowChildPolicy(t)
	t.Setenv("GO_WANT_DCG_SAFE_HELPER", "1")
	root := trustedCaptureRoot(t)
	paths := evidencePaths(root, "signal")
	result := make(chan int, 1)
	go func() {
		result <- Execute(Options{
			StdoutPath: paths[0],
			StderrPath: paths[1],
			StatusPath: paths[2],
			Command:    helperCommand(t, "block"),
			Roots:      []string{root},
			UID:        os.Geteuid(),
			Stdin:      strings.NewReader(""),
		}, io.Discard)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		body, err := os.ReadFile(paths[0])
		if err == nil && string(body) == "ready\n" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child did not become ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := unix.Kill(os.Getpid(), unix.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-result:
		want := 128 + int(unix.SIGTERM)
		if code != want {
			t.Fatalf("code = %d, want %d", code, want)
		}
		if got := string(readFile(t, paths[2])); got != strconv.Itoa(want)+"\n" {
			t.Fatalf("status = %q", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("capture did not finish after forwarded signal")
	}
}

func TestStatusDescriptorDoesNotLeakOnLinux(t *testing.T) {
	allowChildPolicy(t)
	if runtime.GOOS != "linux" {
		t.Skip("/proc descriptor inspection is Linux-specific")
	}
	t.Setenv("GO_WANT_DCG_SAFE_HELPER", "1")
	root := trustedCaptureRoot(t)
	paths := evidencePaths(root, "fds")
	code := Execute(Options{
		StdoutPath: paths[0],
		StderrPath: paths[1],
		StatusPath: paths[2],
		Command:    helperCommand(t, "fds"),
		Roots:      []string{root},
		UID:        os.Geteuid(),
		Stdin:      strings.NewReader(""),
	}, io.Discard)
	if code != 0 {
		t.Fatalf("code = %d", code)
	}
	var links map[string]string
	if err := json.Unmarshal(readFile(t, paths[0]), &links); err != nil {
		t.Fatal(err)
	}
	for fd, target := range links {
		if target == paths[2] {
			t.Fatalf("status descriptor leaked as child fd %s", fd)
		}
		if number, err := strconv.Atoi(fd); err == nil && number > 2 &&
			(target == paths[0] || target == paths[1]) {
			t.Fatalf("capture source descriptor leaked as child fd %s -> %s", fd, target)
		}
	}
}

func TestChildPolicyEvaluatorResults(t *testing.T) {
	tests := []struct {
		name         string
		output       dcgEvaluatorOutput
		runErr       error
		timeout      bool
		wantDecision childPolicyDecision
		wantRuleID   string
		wantErr      string
	}{
		{
			name: "allow",
			output: dcgEvaluatorOutput{
				exitCode: 0,
				stdout:   []byte(`{"index":0,"decision":"allow"}` + "\n"),
			},
			wantDecision: childPolicyAllow,
		},
		{
			name: "deny with rule",
			output: dcgEvaluatorOutput{
				exitCode: 1,
				stdout:   []byte(`{"index":0,"decision":"deny","rule_id":"core.filesystem:rm-rf-root"}` + "\n"),
			},
			wantDecision: childPolicyDeny,
			wantRuleID:   "core.filesystem:rm-rf-root",
		},
		{
			name:         "unavailable",
			runErr:       os.ErrNotExist,
			wantDecision: childPolicyFailure,
			wantErr:      "run DCG policy check",
		},
		{
			name:         "timeout",
			timeout:      true,
			wantDecision: childPolicyFailure,
			wantErr:      "timed out",
		},
		{
			name: "malformed",
			output: dcgEvaluatorOutput{
				exitCode: 0,
				stdout:   []byte("not-json\n"),
			},
			wantDecision: childPolicyFailure,
			wantErr:      "parse DCG response",
		},
		{
			name: "oversized",
			output: dcgEvaluatorOutput{
				exitCode:        0,
				stdout:          bytes.Repeat([]byte{'x'}, childPolicyMaxOutputSize),
				stdoutOversized: true,
			},
			wantDecision: childPolicyFailure,
			wantErr:      "exceeds",
		},
		{
			name: "exit zero deny contradiction",
			output: dcgEvaluatorOutput{
				exitCode: 0,
				stdout:   []byte(`{"index":0,"decision":"deny"}` + "\n"),
			},
			wantDecision: childPolicyFailure,
			wantErr:      "contradicted",
		},
		{
			name: "exit one allow contradiction",
			output: dcgEvaluatorOutput{
				exitCode: 1,
				stdout:   []byte(`{"index":0,"decision":"allow"}` + "\n"),
			},
			wantDecision: childPolicyFailure,
			wantErr:      "contradicted",
		},
		{
			name: "multiple records",
			output: dcgEvaluatorOutput{
				exitCode: 0,
				stdout: []byte(
					`{"index":0,"decision":"allow"}` + "\n" +
						`{"index":1,"decision":"allow"}` + "\n",
				),
			},
			wantDecision: childPolicyFailure,
			wantErr:      "exactly one",
		},
		{
			name: "wrong index",
			output: dcgEvaluatorOutput{
				exitCode: 0,
				stdout:   []byte(`{"index":1,"decision":"allow"}` + "\n"),
			},
			wantDecision: childPolicyFailure,
			wantErr:      "index 0",
		},
		{
			name: "missing decision",
			output: dcgEvaluatorOutput{
				exitCode: 0,
				stdout:   []byte(`{"index":0}` + "\n"),
			},
			wantDecision: childPolicyFailure,
			wantErr:      "missing decision",
		},
		{
			name: "unknown decision",
			output: dcgEvaluatorOutput{
				exitCode: 0,
				stdout:   []byte(`{"index":0,"decision":"warn"}` + "\n"),
			},
			wantDecision: childPolicyFailure,
			wantErr:      "unknown decision",
		},
		{
			name: "unknown exit",
			output: dcgEvaluatorOutput{
				exitCode: 3,
				stdout:   []byte(`{"index":0,"decision":"allow"}` + "\n"),
			},
			wantDecision: childPolicyFailure,
			wantErr:      "status 3",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			hooks := policyTestHooks(t)
			if test.timeout {
				hooks.timeout = 10 * time.Millisecond
				hooks.run = func(ctx context.Context, _ string, _ []string, _ string, _ []string, _ []byte) (dcgEvaluatorOutput, error) {
					<-ctx.Done()
					return dcgEvaluatorOutput{}, ctx.Err()
				}
			} else {
				hooks.run = func(context.Context, string, []string, string, []string, []byte) (dcgEvaluatorOutput, error) {
					return test.output, test.runErr
				}
			}
			result := evaluateChildPolicy([]string{"cmd"}, hooks)
			if result.decision != test.wantDecision {
				t.Fatalf("decision = %v, want %v; err=%v", result.decision, test.wantDecision, result.err)
			}
			if result.ruleID != test.wantRuleID {
				t.Fatalf("ruleID = %q, want %q", result.ruleID, test.wantRuleID)
			}
			if test.wantErr == "" {
				if result.err != nil {
					t.Fatalf("err = %v", result.err)
				}
			} else if result.err == nil || !strings.Contains(result.err.Error(), test.wantErr) {
				t.Fatalf("err = %v, want substring %q", result.err, test.wantErr)
			}
		})
	}
}

func TestChildPolicySynthesizesQuotedBashEvent(t *testing.T) {
	tests := []struct {
		name        string
		command     []string
		wantCommand string
		wantErr     string
	}{
		{
			name:        "empty value",
			command:     []string{"cmd", ""},
			wantCommand: "'cmd' ''",
		},
		{
			name:        "whitespace",
			command:     []string{"cmd", "two words", "\t"},
			wantCommand: "'cmd' 'two words' '\t'",
		},
		{
			name:        "quotes",
			command:     []string{"cmd", "it's", `a"b`},
			wantCommand: "'cmd' 'it'\\''s' 'a\"b'",
		},
		{
			name:        "newlines",
			command:     []string{"cmd", "line\nbreak"},
			wantCommand: "'cmd' 'line\nbreak'",
		},
		{
			name: "metacharacters",
			command: []string{
				"cmd",
				"$HOME",
				"*",
				";",
				"&&",
				"$(touch x)",
				"`whoami`",
				"a|b",
			},
			wantCommand: "'cmd' '$HOME' '*' ';' '&&' '$(touch x)' '`whoami`' 'a|b'",
		},
		{
			name:    "invalid utf8",
			command: []string{"cmd", string([]byte{0xff})},
			wantErr: "valid UTF-8",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			hooks := policyTestHooks(t)
			called := false
			hooks.run = func(_ context.Context, dcgPath string, args []string, _ string, _ []string, stdin []byte) (dcgEvaluatorOutput, error) {
				called = true
				if filepath.Base(dcgPath) != "dcg" {
					t.Fatalf("dcg path = %s", dcgPath)
				}
				wantArgs := []string{"hook", "--batch", "--robot", "--no-color", "--no-suggestions"}
				if strings.Join(args, "\x00") != strings.Join(wantArgs, "\x00") {
					t.Fatalf("args = %#v, want %#v", args, wantArgs)
				}
				var event dcgHookInput
				if err := json.Unmarshal(stdin, &event); err != nil {
					t.Fatalf("decode event: %v\n%s", err, stdin)
				}
				if event.ToolName != "Bash" {
					t.Fatalf("tool name = %q", event.ToolName)
				}
				if got := event.ToolInput["command"]; got != test.wantCommand {
					t.Fatalf("command = %q, want %q", got, test.wantCommand)
				}
				return dcgEvaluatorOutput{
					exitCode: 0,
					stdout:   []byte(`{"index":0,"decision":"allow"}` + "\n"),
				}, nil
			}
			result := evaluateChildPolicy(test.command, hooks)
			if test.wantErr == "" {
				if result.decision != childPolicyAllow || result.err != nil {
					t.Fatalf("result = %+v", result)
				}
				if !called {
					t.Fatal("policy evaluator was not called")
				}
			} else {
				if result.decision != childPolicyFailure || result.err == nil ||
					!strings.Contains(result.err.Error(), test.wantErr) {
					t.Fatalf("result = %+v, want error containing %q", result, test.wantErr)
				}
				if called {
					t.Fatal("policy evaluator was called for invalid argv")
				}
			}
		})
	}
}

func TestChildPolicyRequiresColocatedRegularDCG(t *testing.T) {
	directory := t.TempDir()
	self := filepath.Join(directory, "dcg-safe")
	if err := os.WriteFile(self, []byte("dcg-safe test executable"), 0o755); err != nil {
		t.Fatal(err)
	}
	executable := func() (string, error) { return self, nil }
	if _, err := resolvePeerDCG(executable); err == nil || !strings.Contains(err.Error(), "colocated dcg") {
		t.Fatalf("missing dcg error = %v", err)
	}
	if err := os.Mkdir(filepath.Join(directory, "dcg"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := resolvePeerDCG(executable); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("directory dcg error = %v", err)
	}
	if err := os.Remove(filepath.Join(directory, "dcg")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "dcg"), []byte("dcg test executable"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := resolvePeerDCG(executable); err == nil || !strings.Contains(err.Error(), "executable") {
		t.Fatalf("non-executable dcg error = %v", err)
	}
	if err := os.Chmod(filepath.Join(directory, "dcg"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := resolvePeerDCG(executable); err != nil {
		t.Fatalf("regular executable dcg rejected: %v", err)
	}
}

func TestPolicyDenialDoesNotExecuteConsumeStdinOrReserveFiles(t *testing.T) {
	withChildPolicy(t, func([]string) childPolicyResult {
		return childPolicyResult{
			decision: childPolicyDeny,
			ruleID:   "core.filesystem:rm-rf-root",
		}
	})
	root := trustedCaptureRoot(t)
	paths := evidencePaths(root, "policy-denied")
	sentinel := filepath.Join(root, "child-ran")
	stdin := &trackingReader{}
	var diagnostics bytes.Buffer
	code := Execute(Options{
		StdoutPath: paths[0],
		StderrPath: paths[1],
		StatusPath: paths[2],
		Command:    helperCommand(t, "touch", sentinel),
		Roots:      []string{root},
		UID:        os.Geteuid(),
		Stdin:      stdin,
	}, &diagnostics)
	if code != SetupFailure {
		t.Fatalf("code = %d, diagnostics = %s", code, diagnostics.String())
	}
	if !strings.Contains(diagnostics.String(), "core.filesystem:rm-rf-root") {
		t.Fatalf("diagnostics did not include rule ID: %s", diagnostics.String())
	}
	if stdin.reads != 0 {
		t.Fatalf("stdin was consumed %d times", stdin.reads)
	}
	for _, path := range []string{paths[0], paths[1], paths[2], sentinel} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s exists after policy denial: %v", path, err)
		}
	}
}

func TestPolicyEvaluatorEnvironmentSanitizedAndChildEnvironmentUnchanged(t *testing.T) {
	t.Setenv("GO_WANT_DCG_SAFE_HELPER", "1")
	t.Setenv("HOME", "/caller/home")
	t.Setenv("DCG_CONFIG", "/caller/dcg-config.toml")
	t.Setenv("DCG_POLICY_OVERRIDE", "caller-policy")
	t.Setenv("DCG_SAFE_TEST_ENV", "child-visible")
	t.Setenv("KEEP_ME", "preserved")
	t.Setenv("XDG_CONFIG_HOME", "/caller/xdg")

	cwd := t.TempDir()
	canonicalCWD, err := filepath.EvalSymlinks(cwd)
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(canonicalCWD)
	t.Setenv("PWD", "/caller/pwd")

	var evaluatorCWD string
	var evaluatorEnv []string
	hooks := policyTestHooks(t)
	hooks.lookupHome = func(int) (string, error) { return "/resolved/home", nil }
	hooks.run = func(_ context.Context, _ string, _ []string, cwd string, env []string, _ []byte) (dcgEvaluatorOutput, error) {
		evaluatorCWD = cwd
		evaluatorEnv = append([]string(nil), env...)
		return dcgEvaluatorOutput{
			exitCode: 0,
			stdout:   []byte(`{"index":0,"decision":"allow"}` + "\n"),
		}, nil
	}
	withChildPolicy(t, func(command []string) childPolicyResult {
		return evaluateChildPolicy(command, hooks)
	})

	root := trustedCaptureRoot(t)
	paths := evidencePaths(root, "env")
	code := Execute(Options{
		StdoutPath: paths[0],
		StderrPath: paths[1],
		StatusPath: paths[2],
		Command:    helperCommand(t, "streams"),
		Roots:      []string{root},
		UID:        os.Geteuid(),
		Stdin:      strings.NewReader(""),
	}, io.Discard)
	if code != 7 {
		t.Fatalf("code = %d", code)
	}
	if evaluatorCWD != canonicalCWD {
		t.Fatalf("evaluator cwd = %q, want %q", evaluatorCWD, canonicalCWD)
	}
	evaluatorEnvMap := envMap(evaluatorEnv)
	if got := evaluatorEnvMap["HOME"]; got != "/resolved/home" {
		t.Fatalf("evaluator HOME = %q", got)
	}
	if got := evaluatorEnvMap["PWD"]; got != canonicalCWD {
		t.Fatalf("evaluator PWD = %q, want %q", got, canonicalCWD)
	}
	if got := evaluatorEnvMap["KEEP_ME"]; got != "preserved" {
		t.Fatalf("evaluator KEEP_ME = %q", got)
	}
	for _, name := range []string{
		"DCG_CONFIG",
		"DCG_POLICY_OVERRIDE",
		"DCG_SAFE_TEST_ENV",
		"XDG_CONFIG_HOME",
	} {
		if _, ok := evaluatorEnvMap[name]; ok {
			t.Fatalf("evaluator env retained %s in %#v", name, evaluatorEnvMap)
		}
	}

	var payload struct {
		CWD         string            `json:"cwd"`
		SelectedEnv map[string]string `json:"selected_env"`
	}
	if err := json.Unmarshal(readFile(t, paths[0]), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.CWD != canonicalCWD {
		t.Fatalf("child cwd = %q, want %q", payload.CWD, canonicalCWD)
	}
	wantChildEnv := map[string]string{
		"DCG_CONFIG":          "/caller/dcg-config.toml",
		"DCG_POLICY_OVERRIDE": "caller-policy",
		"DCG_SAFE_TEST_ENV":   "child-visible",
		"HOME":                "/caller/home",
		"KEEP_ME":             "preserved",
		"PWD":                 "/caller/pwd",
		"XDG_CONFIG_HOME":     "/caller/xdg",
	}
	for name, want := range wantChildEnv {
		if got := payload.SelectedEnv[name]; got != want {
			t.Fatalf("child env %s = %q, want %q", name, got, want)
		}
	}
}

func helperCommand(t *testing.T, mode string, arguments ...string) []string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := []string{executable, "-test.run=^TestHelperProcess$", "--", mode}
	return append(command, arguments...)
}

func trustedCaptureRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	root = canonical
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

func evidencePaths(root, prefix string) [3]string {
	return [3]string{
		filepath.Join(root, prefix+".stdout"),
		filepath.Join(root, prefix+".stderr"),
		filepath.Join(root, prefix+".status"),
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func allowChildPolicy(t *testing.T) {
	t.Helper()
	withChildPolicy(t, func([]string) childPolicyResult {
		return childPolicyResult{decision: childPolicyAllow}
	})
}

func withChildPolicy(t *testing.T, check func([]string) childPolicyResult) {
	t.Helper()
	old := childPolicy
	childPolicy = check
	t.Cleanup(func() {
		childPolicy = old
	})
}

func policyTestHooks(t *testing.T) childPolicyHooks {
	t.Helper()
	directory := t.TempDir()
	self := filepath.Join(directory, "dcg-safe")
	if err := os.WriteFile(self, []byte("dcg-safe test executable"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(self, 0o755); err != nil {
		t.Fatal(err)
	}
	dcg := filepath.Join(directory, "dcg")
	if err := os.WriteFile(dcg, []byte("dcg test executable"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dcg, 0o755); err != nil {
		t.Fatal(err)
	}
	return childPolicyHooks{
		executable: func() (string, error) { return self, nil },
		getwd:      os.Getwd,
		lookupHome: func(int) (string, error) {
			return "/home/dcg-safe-test", nil
		},
		environ: os.Environ,
		timeout: time.Second,
	}
}

type trackingReader struct {
	reads int
}

func (reader *trackingReader) Read([]byte) (int, error) {
	reader.reads++
	return 0, io.EOF
}

func envMap(environ []string) map[string]string {
	mapped := map[string]string{}
	for _, entry := range environ {
		name, value, ok := strings.Cut(entry, "=")
		if ok {
			mapped[name] = value
		}
	}
	return mapped
}
