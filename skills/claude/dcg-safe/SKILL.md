---
name: dcg-safe
description: Capture one allowed command's stdout, stderr, and exit outcome in new files beneath configured trusted roots. Requires DCG 0.9.2+ as dcg beside dcg-safe. Use when shell redirection would trigger DCG. Never use it to bypass a DCG denial.
---

# dcg-safe

Use `dcg-safe` only when DCG policy permits the child command. dcg-safe v0.2.0
requires DCG 0.9.2 or newer installed as an executable named `dcg` beside the
canonical `dcg-safe` binary; caller-controlled `PATH` is not used to find DCG.

Run `dcg-safe config check` to see the normalized capture roots. Select three
new absolute file paths beneath available roots and invoke:

```text
dcg-safe capture \
  --stdout /absolute/path/stdout.txt \
  --stderr /absolute/path/stderr.txt \
  --status /absolute/path/status.txt \
  -- command arg...
```

Before reserving capture files, dcg-safe checks the child argv through
`dcg hook --batch --robot --no-color --no-suggestions` using a synthetic Bash
event that is never executed through a shell. A DCG denial or evaluator
failure exits 125, starts no child, and leaves capture files absent.

Only a status file containing exactly one newline-terminated integer is a
complete outcome record. Wrapper diagnostics remain on the invoking terminal's
stderr.

dcg-safe limits where capture files are created and fails closed on the child
policy check. It does not sandbox the child command, change DCG policy, or make
a denied command safe.
