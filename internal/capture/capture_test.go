package capture

import (
	"bytes"
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
			Args  []string `json:"args"`
			CWD   string   `json:"cwd"`
			Env   string   `json:"env"`
			Stdin string   `json:"stdin"`
		}{
			Args:  arguments,
			CWD:   cwd,
			Env:   os.Getenv("DCG_SAFE_TEST_ENV"),
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
