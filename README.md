# dcg-safe

`dcg-safe` v0.2.0 captures the stdout, stderr, and outcome of one child command
in three new files beneath configured trusted roots.

It is an evidence-capture wrapper, not a logger, command sandbox, replacement
for DCG, or temporary-directory manager. Trusted roots constrain only the
capture destinations. Before it reserves those destinations, dcg-safe asks a
co-located DCG 0.9.2+ evaluator whether the exact child command is allowed.
The child inherits the wrapper's working directory, environment, and stdin, and
retains its normal filesystem access.

## Capture a command

```text
dcg-safe capture \
  --stdout /absolute/new/stdout.txt \
  --stderr /absolute/new/stderr.txt \
  --status /absolute/new/status.txt \
  -- command arg...
```

All three paths are mandatory, absolute, explicitly named, and must not already
exist. dcg-safe checks the child command with DCG before reserving any capture
file, then reserves all three before it starts the child. The command is
executed directly as an argument vector; no shell evaluates its arguments or
the synthetic Bash command string sent to DCG.

The status file is authoritative only when its complete contents are an integer
followed by one newline. stdout and stderr are closed before this record is
completed.

| Outcome | Status and wrapper exit |
| --- | ---: |
| Setup or policy check failed; child did not start | 125 (reserved files are absent or rolled back) |
| DCG denied the child command | 125 (no capture files are created) |
| Executable or shebang interpreter missing | 127 |
| Executable cannot be invoked (`EACCES`, `ENOEXEC`, directory, or `exec.ErrDot`) | 126 |
| Other invocation failure | 125 |
| Child exited | Child exit code |
| Child died from a signal | 128 + signal number |
| Capture finalization failed | 125; status is left incomplete where possible |

Invocation failures keep the three captures. Wrapper diagnostics go to the
wrapper's own stderr, not the child's stderr capture.

dcg-safe forwards `SIGINT`, `SIGTERM`, `SIGHUP`, and `SIGQUIT` best-effort to
the direct child. It does not create or supervise a process group.

## Configuration

dcg-safe resolves `~` from the effective UID's account record and deliberately
ignores `$HOME`. Its only config path is:

```text
~/.dcg-safe/config.toml
```

When that file is absent, the embedded [example policy](config.example.toml) is
used without creating anything:

```toml
schema = 1

allowed_roots = [
  "/tmp",
  "~/tmp",
  "~/WebstormProjects",
  "~/Documents",
]
```

Materialize that exact policy with:

```text
dcg-safe config init
```

The command creates `~/.dcg-safe` as mode `0700` and the config as `0600`. It
never overwrites a file. Re-running it with a valid existing policy succeeds;
an invalid or insecure file is reported without modification.

Inspect the effective policy and root availability with:

```text
dcg-safe config check
```

Missing or unusable roots are warnings. Only roots selected by the three
capture destinations are security-validated for a capture, so an unrelated
missing root does not disable a usable one. When configured roots overlap, the
longest matching root controls the destination.

The TOML decoder is strict. Schema values other than 1, unknown keys, duplicate
normalized roots, files larger than 64 KiB, relative roots, environment
references, globs, traversal, repeated separators, and tilde forms other than a
leading `~/` are rejected. An existing config and its directory must be real,
owned by the effective UID, and not group- or other-writable. Existing malformed
or insecure configuration fails closed.

For a selected non-`/tmp` root, dcg-safe rejects symlink components, requires
the root and every destination parent below it to be owned by the effective
UID, and rejects world-writable directories. Group-writable directories such
as mode `0775` are accepted: group members are explicitly part of the trusted
boundary. The platform `/tmp` alias is accepted only after its canonical target
is verified as a root-owned sticky directory.

Final names are created with descriptor-relative `openat`, `O_NOFOLLOW`,
`O_CLOEXEC`, and `O_CREAT|O_EXCL`, verified as regular files, and forced to mode
`0600` even under a hostile umask.

## DCG boundary

dcg-safe v0.2.0 requires DCG 0.9.2 or newer installed as an executable named
`dcg` beside the canonical `dcg-safe` executable. It resolves its own
executable with `os.Executable` and symlink resolution, then invokes only that
adjacent `dcg`; caller-controlled `PATH` is not consulted for the policy
evaluator.

For each capture, dcg-safe POSIX-quotes every child argument and submits one
synthetic Bash hook event to:

```text
dcg hook --batch --robot --no-color --no-suggestions
```

The synthetic command string is policy input only. dcg-safe never evaluates it
through a shell, never calls `dcg test`, and never changes the argument vector
used for the actual child.

Policy evaluation uses the real current working directory and a sanitized
environment. `HOME` is resolved from the effective UID's account record;
`DCG_CONFIG`, `XDG_CONFIG_HOME`, and inherited `DCG_*` variables are ignored
for the evaluator. The actual child still receives the wrapper's original
environment unchanged.

dcg-safe permits the child only when DCG exits 0 and emits exactly one robot
record with `index: 0` and `decision: "allow"`. DCG exit 1 with one valid
`decision: "deny"` record is reported as a policy denial, including `rule_id`
when DCG provides one. Invalid UTF-8 argv, missing or non-executable co-located
DCG, timeouts, output over 64 KiB, malformed JSON, contradictory records, and
unknown evaluator statuses all fail closed with wrapper exit 125. These policy
denials and failures occur before capture files are reserved.

Use the dcg-safe skill when command stdout, stderr, and exit status must be
captured beneath configured roots and shell redirection would trigger DCG. Do
not use it to bypass a DCG denial of the child command.

The expected manual compatibility check for v0.2.0 is DCG 0.9.2 or newer:
inside a disposable Git repository, verify that a benign wrapped child is
captured and a plainly denied child exits 125 without creating capture files.

## Installation and delegated installer

Release archives contain a static `dcg-safe` binary, this README, the MIT
license, `install-skill.sh`, the example policy, and the auditable Claude and
Codex payloads.

The installer installs `dcg-safe` only. For capture to work in v0.2.0, install
DCG 0.9.2 or newer as `dcg` in the same directory as the installed `dcg-safe`
binary, for example `~/.local/bin/dcg` beside `~/.local/bin/dcg-safe`.

The installer implements mise-en-place's delegated schema-1 contract:

```text
./install-skill.sh --plan     --target all   --json --install-root /absolute/staging-home
./install-skill.sh --install  --target all   --json --install-root /absolute/staging-home
./install-skill.sh --uninstall --target all  --json --install-root /absolute/staging-home
./install-skill.sh             --target tools --json --install-root /absolute/staging-home
```

The fourth command demonstrates the default `install` operation.
`--plan`, `--install`, and `--uninstall` are mutually exclusive. Targets are
`tools`, `codex`, `claude`, and `all`:

| Requested target | Installed or removed files |
| --- | --- |
| `tools` | `~/.local/bin/dcg-safe` |
| `codex` | Executable plus Codex skill and metadata |
| `claude` | Executable plus Claude skill and rule |
| `all` | Executable plus both host payloads |

Uninstall mirrors this mapping, so uninstalling either host target also removes
the shared executable. Install results report absolute paths and SHA-256
hashes. Plan and uninstall results omit hashes. With `--json`, stdout contains
only the JSON result.

The executable and payloads are replaced atomically. The installer never
installs, removes, or reports `~/.dcg-safe/config.toml`, and it never modifies
`~/.codex/AGENTS.md`.

`install-skill.sh` prefers an adjacent release binary. In a source checkout it
runs the Go command directly, injecting an exact normalized release tag when
HEAD is tagged and `dev` otherwise.

## Scope and exclusions

Version 0.2.0 does not attempt to defend against hostile same-UID processes or
processes belonging to a trusted group. ACL grants, mount races, network
filesystem semantics, and crash or power-loss durability are outside its
assurance boundary.

It also does not provide TTY job control or process-group supervision. Signals
can be duplicated or ignored by the child; `SIGKILL` cannot be forwarded.
Background descendants can outlive the direct child and can retain inherited
stdout or stderr descriptors.

## Development

The supported build matrix is Linux and macOS on amd64 and arm64 with Go 1.24.

```text
go test ./...
go vet ./...
goreleaser release --snapshot --clean
```

Stable releases are tagged as `vMAJOR.MINOR.PATCH`; `v0.1.0` was the first
stable tag, and v0.2.0 introduces the child-policy gate described above.
