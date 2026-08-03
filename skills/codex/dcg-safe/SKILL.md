---
name: dcg-safe
description: Capture one allowed command's stdout, stderr, and exit outcome in new files beneath dcg-safe trusted roots. Requires DCG 0.9.2+ as dcg beside dcg-safe. Use when shell redirection would trigger DCG and evidence capture is required. Never use it to bypass a DCG denial.
---

# dcg-safe

Use `dcg-safe` only to capture evidence for a child command that is permitted
by DCG policy. dcg-safe v0.2.0 requires DCG 0.9.2 or newer installed as an
executable named `dcg` beside the canonical `dcg-safe` binary; it does not find
DCG through caller-controlled `PATH`.

Choose three new, explicitly named files beneath roots reported as available by
`dcg-safe config check`, then run:

```text
dcg-safe capture \
  --stdout /absolute/path/stdout.txt \
  --stderr /absolute/path/stderr.txt \
  --status /absolute/path/status.txt \
  -- command arg...
```

Before reserving capture files, dcg-safe sends a synthetic Bash event for the
child argv to `dcg hook --batch --robot --no-color --no-suggestions`. The
synthetic command is policy input only and is never executed through a shell.
If DCG denies the child or the policy evaluator is unavailable, malformed,
timed out, or contradictory, dcg-safe exits 125, starts no child, and leaves the
capture files absent.

The status file is authoritative only when it contains exactly one
newline-terminated integer. A missing or incomplete status record means capture
finalization did not complete. Read stdout and stderr as raw command output; the
wrapper writes its own diagnostics to the invoking terminal's stderr.

dcg-safe constrains capture destinations and fails closed on the child policy
check. It does not sandbox the child process, restrict descendants, or make a
denied command safe.
