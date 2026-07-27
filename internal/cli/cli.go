// Package cli dispatches dcg-safe commands.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/bigbizze/dcg-safe/internal/account"
	"github.com/bigbizze/dcg-safe/internal/capture"
	"github.com/bigbizze/dcg-safe/internal/config"
	"github.com/bigbizze/dcg-safe/internal/install"
	"github.com/bigbizze/dcg-safe/internal/securepath"
	"github.com/bigbizze/dcg-safe/internal/version"
)

const usage = `dcg-safe captures one child command's evidence beneath configured roots.

Usage:
  dcg-safe capture --stdout ABSOLUTE_PATH --stderr ABSOLUTE_PATH --status ABSOLUTE_PATH -- COMMAND [ARG...]
  dcg-safe config init
  dcg-safe config check
  dcg-safe --version
`

// Run dispatches args and returns the process exit code.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "--version":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "dcg-safe: --version accepts no arguments")
			return 2
		}
		fmt.Fprintf(stdout, "dcg-safe %s\n", version.String())
		return 0
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return 0
	case "capture":
		return runCapture(args[1:], stdin, stderr)
	case "config":
		return runConfig(args[1:], stdout, stderr)
	case "internal":
		if len(args) >= 2 && args[1] == "delegate-install" {
			executable, err := os.Executable()
			if err != nil {
				fmt.Fprintln(stderr, "dcg-safe delegate-install:", err)
				return 1
			}
			return install.Run(args[2:], stdout, stderr, executable)
		}
		fmt.Fprintln(stderr, "dcg-safe: unknown internal command")
		return 2
	default:
		fmt.Fprintf(stderr, "dcg-safe: unknown command %q\n", args[0])
		fmt.Fprint(stderr, usage)
		return 2
	}
}

type captureArgs struct {
	stdoutPath string
	stderrPath string
	statusPath string
	command    []string
}

func runCapture(args []string, stdin io.Reader, stderr io.Writer) int {
	parsed, err := parseCapture(args)
	if err != nil {
		fmt.Fprintln(stderr, "dcg-safe: capture:", err)
		return capture.SetupFailure
	}
	identity, err := account.Effective()
	if err != nil {
		fmt.Fprintln(stderr, "dcg-safe: identity:", err)
		return capture.SetupFailure
	}
	policy, err := config.Load(identity)
	if err != nil {
		fmt.Fprintln(stderr, "dcg-safe: config:", err)
		return capture.SetupFailure
	}
	return capture.Execute(capture.Options{
		StdoutPath: parsed.stdoutPath,
		StderrPath: parsed.stderrPath,
		StatusPath: parsed.statusPath,
		Command:    parsed.command,
		Roots:      policy.Roots,
		UID:        identity.UID,
		Stdin:      stdin,
	}, stderr)
}

func parseCapture(args []string) (captureArgs, error) {
	var parsed captureArgs
	seen := map[string]bool{}
	for index := 0; index < len(args); {
		argument := args[index]
		if argument == "--" {
			parsed.command = append([]string(nil), args[index+1:]...)
			if len(parsed.command) == 0 || parsed.command[0] == "" {
				return captureArgs{}, errors.New("missing command after --")
			}
			if parsed.stdoutPath == "" || parsed.stderrPath == "" || parsed.statusPath == "" {
				return captureArgs{}, errors.New("--stdout, --stderr, and --status are all required")
			}
			return parsed, nil
		}

		name, value, hasInlineValue := strings.Cut(argument, "=")
		switch name {
		case "--stdout", "--stderr", "--status":
		default:
			return captureArgs{}, fmt.Errorf("unknown option %q (a literal -- separator is required)", argument)
		}
		if seen[name] {
			return captureArgs{}, fmt.Errorf("%s may be specified only once", name)
		}
		seen[name] = true
		if !hasInlineValue {
			index++
			if index >= len(args) || args[index] == "--" {
				return captureArgs{}, fmt.Errorf("%s requires a path", name)
			}
			value = args[index]
		}
		if value == "" {
			return captureArgs{}, fmt.Errorf("%s requires a non-empty path", name)
		}
		switch name {
		case "--stdout":
			parsed.stdoutPath = value
		case "--stderr":
			parsed.stderrPath = value
		case "--status":
			parsed.statusPath = value
		}
		index++
	}
	return captureArgs{}, errors.New("missing literal -- separator and command")
}

func runConfig(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "dcg-safe: config requires exactly one of init or check")
		return 2
	}
	identity, err := account.Effective()
	if err != nil {
		fmt.Fprintln(stderr, "dcg-safe: identity:", err)
		return 1
	}
	switch args[0] {
	case "init":
		created, err := config.Init(identity)
		if err != nil {
			fmt.Fprintln(stderr, "dcg-safe: config init:", err)
			return 1
		}
		if created {
			fmt.Fprintf(stdout, "created %s\n", config.Path(identity))
		} else {
			fmt.Fprintf(stdout, "valid config already exists: %s\n", config.Path(identity))
		}
		return 0
	case "check":
		policy, err := config.Load(identity)
		if err != nil {
			fmt.Fprintln(stderr, "dcg-safe: config check:", err)
			return 1
		}
		if policy.Defaults {
			fmt.Fprintln(stdout, "config: embedded defaults (config file absent)")
		} else {
			fmt.Fprintf(stdout, "config: %s\n", policy.ConfigPath)
		}
		for _, root := range policy.Roots {
			if err := securepath.CheckRoot(root, identity.UID); err != nil {
				fmt.Fprintf(stdout, "root: %s [unavailable]\n", root)
				fmt.Fprintf(stderr, "dcg-safe: warning: root %s is missing or currently unusable: %v\n", root, err)
				continue
			}
			fmt.Fprintf(stdout, "root: %s [available]\n", root)
		}
		return 0
	default:
		fmt.Fprintf(stderr, "dcg-safe: unknown config command %q\n", args[0])
		return 2
	}
}
