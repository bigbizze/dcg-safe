// Package install implements the mise-en-place delegated installer contract.
package install

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	dcgsafe "github.com/bigbizze/dcg-safe"
	"github.com/bigbizze/dcg-safe/internal/version"
)

const codexNotice = "Use the dcg-safe skill when command stdout, stderr, and exit status must be captured beneath configured roots and shell redirection would trigger DCG. Do not use it to bypass a DCG denial of the child command."

// Result is the schema-1 delegated installer response.
type Result struct {
	Schema    int                     `json:"schema"`
	Name      string                  `json:"name"`
	Version   string                  `json:"version"`
	Operation string                  `json:"operation"`
	Kind      string                  `json:"kind"`
	Targets   map[string]TargetResult `json:"targets"`
	Warnings  []string                `json:"warnings"`
	Notices   []string                `json:"notices"`
}

type TargetResult struct {
	Files []FileResult `json:"files"`
}

type FileResult struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256,omitempty"`
}

// Options is a parsed delegated installation request.
type Options struct {
	Operation   string
	Target      string
	JSON        bool
	InstallRoot string
	Executable  string
}

type plannedFile struct {
	target string
	path   string
	mode   os.FileMode
	body   []byte
	tool   bool
}

// Run parses, executes, and renders one delegated installer request.
func Run(args []string, stdout, stderr io.Writer, executable string) int {
	options, err := parse(args, executable)
	if err != nil {
		fmt.Fprintln(stderr, "dcg-safe delegate-install:", err)
		return 2
	}
	result, err := Execute(options)
	if err != nil {
		fmt.Fprintln(stderr, "dcg-safe delegate-install:", err)
		return 1
	}
	if options.JSON {
		if err := json.NewEncoder(stdout).Encode(result); err != nil {
			fmt.Fprintln(stderr, "dcg-safe delegate-install:", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "%s %s %s\n", result.Name, result.Version, result.Operation)
	for _, target := range sortedTargetNames(result.Targets) {
		for _, file := range result.Targets[target].Files {
			fmt.Fprintf(stdout, "%s: %s\n", target, file.Path)
		}
	}
	for _, notice := range result.Notices {
		fmt.Fprintf(stdout, "notice: %s\n", notice)
	}
	return 0
}

// Execute applies one validated request.
func Execute(options Options) (Result, error) {
	if options.Operation == "" {
		options.Operation = "install"
	}
	if options.Target == "" {
		options.Target = "all"
	}
	switch options.Operation {
	case "plan", "install", "uninstall":
	default:
		return Result{}, errors.New("operation must be plan, install, or uninstall")
	}
	switch options.Target {
	case "claude", "codex", "tools", "all":
	default:
		return Result{}, errors.New("--target must be claude, codex, tools, or all")
	}
	root, err := installRoot(options.InstallRoot)
	if err != nil {
		return Result{}, err
	}
	plan, err := buildPlan(root, options.Target)
	if err != nil {
		return Result{}, err
	}
	if options.Operation == "install" && options.Executable == "" {
		return Result{}, errors.New("running executable path is required")
	}

	result := Result{
		Schema:    1,
		Name:      "dcg-safe",
		Version:   version.String(),
		Operation: options.Operation,
		Kind:      "delegated",
		Targets:   map[string]TargetResult{},
		Warnings:  []string{},
		Notices:   []string{},
	}
	for _, file := range plan {
		if _, ok := result.Targets[file.target]; !ok {
			result.Targets[file.target] = TargetResult{Files: []FileResult{}}
		}
		switch options.Operation {
		case "plan":
		case "install":
			var body []byte
			if file.tool {
				info, err := os.Stat(options.Executable)
				if err != nil {
					return Result{}, fmt.Errorf("inspect executable: %w", err)
				}
				if !info.Mode().IsRegular() {
					return Result{}, errors.New("running executable must be a regular file")
				}
				body, err = os.ReadFile(options.Executable)
				if err != nil {
					return Result{}, fmt.Errorf("read executable: %w", err)
				}
			} else {
				body = file.body
			}
			if err := writeAtomic(file.path, body, file.mode); err != nil {
				return Result{}, fmt.Errorf("install %s: %w", file.path, err)
			}
		case "uninstall":
			if err := os.Remove(file.path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return Result{}, fmt.Errorf("uninstall %s: %w", file.path, err)
			}
		}
		entry := FileResult{Path: file.path}
		if options.Operation == "install" {
			sum, err := fileSHA256(file.path)
			if err != nil {
				return Result{}, fmt.Errorf("hash %s: %w", file.path, err)
			}
			entry.SHA256 = sum
		}
		target := result.Targets[file.target]
		target.Files = append(target.Files, entry)
		result.Targets[file.target] = target
	}
	for targetName, target := range result.Targets {
		sort.Slice(target.Files, func(i, j int) bool {
			return target.Files[i].Path < target.Files[j].Path
		})
		result.Targets[targetName] = target
	}
	if options.Operation != "uninstall" && (options.Target == "codex" || options.Target == "all") {
		result.Notices = append(result.Notices, codexNotice)
	}
	return result, nil
}

func parse(args []string, executable string) (Options, error) {
	flags := flag.NewFlagSet("delegate-install", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	options := Options{Executable: executable}
	selectedOperations := 0
	selectOperation := func(operation string) func(string) error {
		return func(value string) error {
			enabled, err := strconv.ParseBool(value)
			if err != nil {
				return err
			}
			if !enabled {
				return nil
			}
			selectedOperations++
			if selectedOperations > 1 {
				return errors.New("--plan, --install, and --uninstall are mutually exclusive")
			}
			options.Operation = operation
			return nil
		}
	}
	flags.BoolFunc("plan", "report the installation plan", selectOperation("plan"))
	flags.BoolFunc("install", "install files (default)", selectOperation("install"))
	flags.BoolFunc("uninstall", "uninstall files", selectOperation("uninstall"))
	flags.StringVar(&options.Target, "target", "all", "claude|codex|tools|all")
	flags.BoolVar(&options.JSON, "json", false, "emit only JSON on stdout")
	flags.StringVar(&options.InstallRoot, "install-root", "", "absolute staging home")
	if err := flags.Parse(args); err != nil {
		return Options{}, err
	}
	if flags.NArg() != 0 {
		return Options{}, errors.New("unexpected positional arguments")
	}
	return options, nil
}

func installRoot(value string) (string, error) {
	if value == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve install home: %w", err)
		}
		value = home
	}
	if !filepath.IsAbs(value) {
		return "", errors.New("--install-root must be absolute")
	}
	if filepath.Clean(value) != value {
		return "", errors.New("--install-root must already be normalized")
	}
	return filepath.Clean(value), nil
}

func buildPlan(root, requestedTarget string) ([]plannedFile, error) {
	includeTools := true
	includeCodex := requestedTarget == "codex" || requestedTarget == "all"
	includeClaude := requestedTarget == "claude" || requestedTarget == "all"
	if requestedTarget == "tools" {
		includeCodex = false
		includeClaude = false
	}

	var plan []plannedFile
	if includeTools {
		plan = append(plan, plannedFile{
			target: "tools",
			path:   filepath.Join(root, ".local", "bin", "dcg-safe"),
			mode:   0o755,
			tool:   true,
		})
	}
	if includeCodex {
		plan = append(plan,
			plannedFile{
				target: "codex",
				path:   filepath.Join(root, ".codex", "skills", "dcg-safe", "SKILL.md"),
				mode:   0o644,
				body:   []byte(dcgsafe.CodexSkill),
			},
			plannedFile{
				target: "codex",
				path:   filepath.Join(root, ".codex", "skills", "dcg-safe", "agents", "openai.yaml"),
				mode:   0o644,
				body:   []byte(dcgsafe.CodexMetadata),
			},
		)
	}
	if includeClaude {
		plan = append(plan,
			plannedFile{
				target: "claude",
				path:   filepath.Join(root, ".claude", "skills", "dcg-safe", "SKILL.md"),
				mode:   0o644,
				body:   []byte(dcgsafe.ClaudeSkill),
			},
			plannedFile{
				target: "claude",
				path:   filepath.Join(root, ".claude", "rules", "dcg-safe.md"),
				mode:   0o644,
				body:   []byte(dcgsafe.ClaudeRule),
			},
		)
	}
	for _, file := range plan {
		if !filepath.IsAbs(file.path) || !pathWithin(file.path, root) {
			return nil, fmt.Errorf("planned path escapes staging root: %s", file.path)
		}
	}
	return plan, nil
}

func pathWithin(path, root string) bool {
	if path == root {
		return true
	}
	if root == string(filepath.Separator) {
		return strings.HasPrefix(path, root)
	}
	return strings.HasPrefix(path, root+string(filepath.Separator))
}

func writeAtomic(destination string, body []byte, mode os.FileMode) error {
	directory := filepath.Dir(destination)
	if err := mkdirAllExact(directory, 0o755); err != nil {
		return err
	}
	temp, err := os.CreateTemp(directory, "dcg-safe-install-*.tmp")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(tempPath)
		}
	}()
	if _, err := temp.Write(body); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Chmod(mode); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, destination); err != nil {
		return err
	}
	keep = true
	return syncDirectory(directory)
}

func mkdirAllExact(path string, mode os.FileMode) error {
	var missing []string
	current := path
	for {
		info, err := os.Stat(current)
		if err == nil {
			if !info.IsDir() {
				return fmt.Errorf("%s is not a directory", current)
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		missing = append(missing, current)
		parent := filepath.Dir(current)
		if parent == current {
			return fmt.Errorf("no existing ancestor for %s", path)
		}
		current = parent
	}
	for index := len(missing) - 1; index >= 0; index-- {
		directory := missing[index]
		if err := os.Mkdir(directory, mode); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		if err := os.Chmod(directory, mode); err != nil {
			return err
		}
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func sortedTargetNames(targets map[string]TargetResult) []string {
	names := make([]string, 0, len(targets))
	for name := range targets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
