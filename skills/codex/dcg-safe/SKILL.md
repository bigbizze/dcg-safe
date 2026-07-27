---
name: dcg-safe
description: Capture one command's stdout, stderr, and exit outcome in new files beneath dcg-safe trusted roots. Use when shell redirection would trigger DCG and evidence capture is required. Never use it to bypass a DCG denial of the child command.
---

# dcg-safe

Use `dcg-safe` only to capture evidence for a child command that is itself
permitted by the normal DCG policy.

Choose three new, explicitly named files beneath roots reported as available by
`dcg-safe config check`, then run:

```text
dcg-safe capture \
  --stdout /absolute/path/stdout.txt \
  --stderr /absolute/path/stderr.txt \
  --status /absolute/path/status.txt \
  -- command arg...
```

The status file is authoritative only when it contains exactly one
newline-terminated integer. A missing or incomplete status record means capture
finalization did not complete. Read stdout and stderr as raw command output; the
wrapper writes its own diagnostics to the invoking terminal's stderr.

dcg-safe constrains capture destinations. It does not restrict the child
process's working directory, environment, filesystem access, or descendants,
and it does not make a denied command safe.
