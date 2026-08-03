package capture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	childPolicyTimeout       = 5 * time.Second
	childPolicyMaxOutputSize = 64 * 1024
	minimumDCGVersion        = "0.9.2"
)

type childPolicyDecision int

const (
	childPolicyFailure childPolicyDecision = iota
	childPolicyAllow
	childPolicyDeny
)

type childPolicyResult struct {
	decision childPolicyDecision
	ruleID   string
	err      error
}

type childPolicyHooks struct {
	executable func() (string, error)
	getwd      func() (string, error)
	lookupHome func(int) (string, error)
	environ    func() []string
	run        func(context.Context, string, []string, string, []string, []byte) (dcgEvaluatorOutput, error)
	timeout    time.Duration
}

type dcgEvaluatorOutput struct {
	exitCode        int
	stdout          []byte
	stderr          []byte
	stdoutOversized bool
	stderrOversized bool
}

type dcgHookInput struct {
	ToolName  string            `json:"tool_name"`
	ToolInput map[string]string `json:"tool_input"`
}

type dcgHookRecord struct {
	Index    *int    `json:"index"`
	Decision *string `json:"decision"`
	RuleID   *string `json:"rule_id,omitempty"`
}

var childPolicy = func(command []string) childPolicyResult {
	return evaluateChildPolicy(command, defaultChildPolicyHooks())
}

func defaultChildPolicyHooks() childPolicyHooks {
	return childPolicyHooks{
		executable: os.Executable,
		getwd:      os.Getwd,
		lookupHome: lookupEffectiveHome,
		environ:    os.Environ,
		run:        runDCGPolicyEvaluator,
		timeout:    childPolicyTimeout,
	}
}

func evaluateChildPolicy(command []string, hooks childPolicyHooks) childPolicyResult {
	if hooks.timeout <= 0 {
		hooks.timeout = childPolicyTimeout
	}
	if hooks.executable == nil {
		hooks.executable = os.Executable
	}
	if hooks.getwd == nil {
		hooks.getwd = os.Getwd
	}
	if hooks.lookupHome == nil {
		hooks.lookupHome = lookupEffectiveHome
	}
	if hooks.environ == nil {
		hooks.environ = os.Environ
	}
	if hooks.run == nil {
		hooks.run = runDCGPolicyEvaluator
	}

	event, err := childPolicyHookEvent(command)
	if err != nil {
		return childPolicyResult{decision: childPolicyFailure, err: err}
	}
	dcgPath, err := resolvePeerDCG(hooks.executable)
	if err != nil {
		return childPolicyResult{decision: childPolicyFailure, err: err}
	}
	cwd, err := hooks.getwd()
	if err != nil {
		return childPolicyResult{decision: childPolicyFailure, err: fmt.Errorf("resolve cwd: %w", err)}
	}
	home, err := hooks.lookupHome(os.Geteuid())
	if err != nil {
		return childPolicyResult{decision: childPolicyFailure, err: err}
	}
	env := sanitizedEvaluatorEnv(hooks.environ(), home, cwd)

	ctx, cancel := context.WithTimeout(context.Background(), hooks.timeout)
	defer cancel()
	if err := verifyDCGVersion(ctx, hooks, dcgPath, cwd, env); err != nil {
		return childPolicyResult{decision: childPolicyFailure, err: err}
	}
	output, err := hooks.run(
		ctx,
		dcgPath,
		[]string{"hook", "--batch", "--robot", "--no-color", "--no-suggestions"},
		cwd,
		env,
		event,
	)
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return childPolicyResult{decision: childPolicyFailure, err: errors.New("DCG policy check timed out")}
	}
	if err != nil {
		return childPolicyResult{decision: childPolicyFailure, err: fmt.Errorf("run DCG policy check: %w", err)}
	}
	if output.stdoutOversized || output.stderrOversized ||
		len(output.stdout) > childPolicyMaxOutputSize || len(output.stderr) > childPolicyMaxOutputSize {
		return childPolicyResult{
			decision: childPolicyFailure,
			err:      fmt.Errorf("DCG policy check output exceeds %d bytes", childPolicyMaxOutputSize),
		}
	}
	return interpretDCGPolicyOutput(output.exitCode, output.stdout)
}

func verifyDCGVersion(ctx context.Context, hooks childPolicyHooks, dcgPath, cwd string, env []string) error {
	output, err := hooks.run(ctx, dcgPath, []string{"--version"}, cwd, env, nil)
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return errors.New("DCG version check timed out")
	}
	if err != nil {
		return fmt.Errorf("run DCG version check: %w", err)
	}
	if output.stdoutOversized || output.stderrOversized ||
		len(output.stdout) > childPolicyMaxOutputSize || len(output.stderr) > childPolicyMaxOutputSize {
		return fmt.Errorf("DCG version check output exceeds %d bytes", childPolicyMaxOutputSize)
	}
	if output.exitCode != 0 {
		return fmt.Errorf("DCG version check exited with status %d", output.exitCode)
	}
	version, err := parseDCGVersion(output.stdout)
	if err != nil {
		return err
	}
	if compareDCGVersion(version, dcgVersion{major: 0, minor: 9, patch: 2}) < 0 {
		return fmt.Errorf("DCG %s is unsupported; require %s+", version.String(), minimumDCGVersion)
	}
	return nil
}

func childPolicyHookEvent(command []string) ([]byte, error) {
	quoted := make([]string, 0, len(command))
	for index, argument := range command {
		if !utf8.ValidString(argument) {
			return nil, fmt.Errorf("argv[%d] is not valid UTF-8", index)
		}
		if strings.IndexByte(argument, 0) >= 0 {
			return nil, fmt.Errorf("argv[%d] contains NUL", index)
		}
		quoted = append(quoted, posixQuote(argument))
	}
	input := dcgHookInput{
		ToolName: "Bash",
		ToolInput: map[string]string{
			"command": strings.Join(quoted, " "),
		},
	}
	body, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("encode DCG policy event: %w", err)
	}
	return append(body, '\n'), nil
}

func posixQuote(value string) string {
	if value == "" {
		return "''"
	}
	var quoted strings.Builder
	quoted.Grow(len(value) + 2)
	quoted.WriteByte('\'')
	for _, char := range value {
		if char == '\'' {
			quoted.WriteString("'\\''")
			continue
		}
		quoted.WriteRune(char)
	}
	quoted.WriteByte('\'')
	return quoted.String()
}

func resolvePeerDCG(executable func() (string, error)) (string, error) {
	self, err := executable()
	if err != nil {
		return "", fmt.Errorf("resolve dcg-safe executable: %w", err)
	}
	if self == "" {
		return "", errors.New("resolve dcg-safe executable: empty path")
	}
	if !filepath.IsAbs(self) {
		self, err = filepath.Abs(self)
		if err != nil {
			return "", fmt.Errorf("resolve dcg-safe executable: %w", err)
		}
	}
	self, err = filepath.EvalSymlinks(self)
	if err != nil {
		return "", fmt.Errorf("resolve dcg-safe executable: %w", err)
	}
	selfInfo, err := os.Stat(self)
	if err != nil {
		return "", fmt.Errorf("inspect dcg-safe executable: %w", err)
	}
	if !selfInfo.Mode().IsRegular() {
		return "", errors.New("dcg-safe executable must resolve to a regular file")
	}

	dcgPath := filepath.Join(filepath.Dir(self), "dcg")
	dcgInfo, err := os.Lstat(dcgPath)
	if err != nil {
		return "", fmt.Errorf("inspect colocated dcg executable: %w", err)
	}
	if !dcgInfo.Mode().IsRegular() {
		return "", errors.New("colocated dcg must be a regular file")
	}
	if dcgInfo.Mode().Perm()&0o111 == 0 {
		return "", errors.New("colocated dcg must be executable")
	}
	return dcgPath, nil
}

func lookupEffectiveHome(uid int) (string, error) {
	entry, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return "", fmt.Errorf("look up effective UID %d: %w", uid, err)
	}
	if entry.HomeDir == "" {
		return "", fmt.Errorf("effective UID %d has no account home", uid)
	}
	return entry.HomeDir, nil
}

func sanitizedEvaluatorEnv(environ []string, home, cwd string) []string {
	clean := make([]string, 0, len(environ)+2)
	for _, entry := range environ {
		name, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if name == "HOME" || name == "PWD" || name == "DCG_CONFIG" ||
			name == "XDG_CONFIG_HOME" || strings.HasPrefix(name, "DCG_") {
			continue
		}
		clean = append(clean, entry)
	}
	clean = append(clean, "HOME="+home, "PWD="+cwd)
	return clean
}

func runDCGPolicyEvaluator(
	ctx context.Context,
	dcgPath string,
	args []string,
	cwd string,
	env []string,
	stdin []byte,
) (dcgEvaluatorOutput, error) {
	command := exec.CommandContext(ctx, dcgPath, args...)
	command.WaitDelay = 100 * time.Millisecond
	command.Dir = cwd
	command.Env = env
	command.Stdin = bytes.NewReader(stdin)

	limit := &outputLimit{remaining: childPolicyMaxOutputSize}
	var stdout, stderr limitedOutput
	stdout.limit = limit
	stderr.limit = limit
	command.Stdout = &stdout
	command.Stderr = &stderr

	err := command.Run()
	output := dcgEvaluatorOutput{
		exitCode:        0,
		stdout:          stdout.Bytes(),
		stderr:          stderr.Bytes(),
		stdoutOversized: stdout.Oversized(),
		stderrOversized: stderr.Oversized(),
	}
	if err == nil {
		return output, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		output.exitCode = exitErr.ExitCode()
		return output, nil
	}
	return output, err
}

type limitedOutput struct {
	limit *outputLimit
	body  bytes.Buffer
}

type outputLimit struct {
	mu        sync.Mutex
	remaining int
	oversized bool
}

func (output *limitedOutput) Write(body []byte) (int, error) {
	if output.limit == nil {
		_, _ = output.body.Write(body)
		return len(body), nil
	}
	output.limit.mu.Lock()
	defer output.limit.mu.Unlock()
	if output.limit.remaining <= 0 {
		output.limit.oversized = output.limit.oversized || len(body) > 0
		return len(body), nil
	}
	if len(body) > output.limit.remaining {
		_, _ = output.body.Write(body[:output.limit.remaining])
		output.limit.remaining = 0
		output.limit.oversized = true
		return len(body), nil
	}
	_, _ = output.body.Write(body)
	output.limit.remaining -= len(body)
	return len(body), nil
}

func (output *limitedOutput) Bytes() []byte {
	return output.body.Bytes()
}

func (output *limitedOutput) Oversized() bool {
	if output.limit == nil {
		return false
	}
	output.limit.mu.Lock()
	defer output.limit.mu.Unlock()
	return output.limit.oversized
}

func interpretDCGPolicyOutput(exitCode int, stdout []byte) childPolicyResult {
	record, err := parseDCGHookRecord(stdout)
	if err != nil {
		return childPolicyResult{decision: childPolicyFailure, err: err}
	}
	if record.Index == nil || *record.Index != 0 {
		return childPolicyResult{decision: childPolicyFailure, err: errors.New("DCG response must contain index 0")}
	}
	if record.Decision == nil {
		return childPolicyResult{decision: childPolicyFailure, err: errors.New("DCG response is missing decision")}
	}

	switch exitCode {
	case 0:
		if *record.Decision == "allow" {
			return childPolicyResult{decision: childPolicyAllow}
		}
		if *record.Decision == "deny" {
			return childPolicyResult{decision: childPolicyFailure, err: errors.New("DCG allowed exit contradicted deny response")}
		}
	case 1:
		if *record.Decision == "deny" {
			result := childPolicyResult{decision: childPolicyDeny}
			if record.RuleID != nil {
				result.ruleID = *record.RuleID
			}
			return result
		}
		if *record.Decision == "allow" {
			return childPolicyResult{decision: childPolicyFailure, err: errors.New("DCG denied exit contradicted allow response")}
		}
	default:
		return childPolicyResult{
			decision: childPolicyFailure,
			err:      fmt.Errorf("DCG policy check exited with status %d", exitCode),
		}
	}
	return childPolicyResult{
		decision: childPolicyFailure,
		err:      fmt.Errorf("DCG returned unknown decision %q", *record.Decision),
	}
}

func parseDCGHookRecord(stdout []byte) (dcgHookRecord, error) {
	if !utf8.Valid(stdout) {
		return dcgHookRecord{}, errors.New("DCG response is not valid UTF-8")
	}
	trimmed := trimJSONWhitespace(stdout)
	if len(trimmed) == 0 {
		return dcgHookRecord{}, errors.New("DCG response is empty")
	}
	if len(trimmed) > childPolicyMaxOutputSize {
		return dcgHookRecord{}, fmt.Errorf("DCG policy check output exceeds %d bytes", childPolicyMaxOutputSize)
	}
	if bytes.Contains(trimmed, []byte{'\n'}) {
		return dcgHookRecord{}, errors.New("DCG response must contain exactly one JSONL record")
	}
	if bytes.Contains(trimmed, []byte{'\r'}) {
		return dcgHookRecord{}, errors.New("DCG response must contain exactly one JSONL record")
	}

	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil {
		return dcgHookRecord{}, fmt.Errorf("parse DCG response: %w", err)
	}
	delim, ok := token.(json.Delim)
	if !ok || delim != '{' {
		return dcgHookRecord{}, errors.New("DCG response must be a JSON object")
	}
	var record dcgHookRecord
	seen := map[string]struct{}{}
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return dcgHookRecord{}, fmt.Errorf("parse DCG response: %w", err)
		}
		key, ok := keyToken.(string)
		if !ok {
			return dcgHookRecord{}, errors.New("DCG response object contains a non-string key")
		}
		if _, ok := seen[key]; ok {
			return dcgHookRecord{}, fmt.Errorf("DCG response contains duplicate %q field", key)
		}
		seen[key] = struct{}{}
		switch key {
		case "index":
			var index int
			if err := decoder.Decode(&index); err != nil {
				return dcgHookRecord{}, fmt.Errorf("parse DCG response index: %w", err)
			}
			record.Index = &index
		case "decision":
			var decision string
			if err := decoder.Decode(&decision); err != nil {
				return dcgHookRecord{}, fmt.Errorf("parse DCG response decision: %w", err)
			}
			record.Decision = &decision
		case "rule_id":
			var ruleID string
			if err := decoder.Decode(&ruleID); err != nil {
				return dcgHookRecord{}, fmt.Errorf("parse DCG response rule_id: %w", err)
			}
			record.RuleID = &ruleID
		default:
			var ignored json.RawMessage
			if err := decoder.Decode(&ignored); err != nil {
				return dcgHookRecord{}, fmt.Errorf("parse DCG response %s: %w", key, err)
			}
		}
	}
	endToken, err := decoder.Token()
	if err != nil {
		return dcgHookRecord{}, fmt.Errorf("parse DCG response: %w", err)
	}
	end, ok := endToken.(json.Delim)
	if !ok || end != '}' {
		return dcgHookRecord{}, errors.New("DCG response object is incomplete")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return dcgHookRecord{}, errors.New("DCG response contains trailing JSON")
	}
	return record, nil
}

func trimJSONWhitespace(body []byte) []byte {
	start := 0
	for start < len(body) && isJSONWhitespace(body[start]) {
		start++
	}
	end := len(body)
	for end > start && isJSONWhitespace(body[end-1]) {
		end--
	}
	return body[start:end]
}

func isJSONWhitespace(value byte) bool {
	switch value {
	case ' ', '\t', '\r', '\n':
		return true
	default:
		return false
	}
}

type dcgVersion struct {
	major int
	minor int
	patch int
}

func (version dcgVersion) String() string {
	return fmt.Sprintf("%d.%d.%d", version.major, version.minor, version.patch)
}

func parseDCGVersion(stdout []byte) (dcgVersion, error) {
	if !utf8.Valid(stdout) {
		return dcgVersion{}, errors.New("DCG version output is not valid UTF-8")
	}
	fields := strings.FieldsFunc(string(stdout), func(char rune) bool {
		return char < '0' || char > '9'
	})
	for index := 0; index+2 < len(fields); index++ {
		major, majorErr := strconv.Atoi(fields[index])
		minor, minorErr := strconv.Atoi(fields[index+1])
		patch, patchErr := strconv.Atoi(fields[index+2])
		if majorErr == nil && minorErr == nil && patchErr == nil {
			return dcgVersion{major: major, minor: minor, patch: patch}, nil
		}
	}
	return dcgVersion{}, errors.New("DCG version output did not contain a semantic version")
}

func compareDCGVersion(left, right dcgVersion) int {
	switch {
	case left.major != right.major:
		return left.major - right.major
	case left.minor != right.minor:
		return left.minor - right.minor
	default:
		return left.patch - right.patch
	}
}
