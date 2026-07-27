---
name: dcg-safe
description: Capture one command's stdout, stderr, and exit outcome in new files beneath configured trusted roots. Use when shell redirection would trigger DCG. Never use it to bypass a DCG denial of the child command.
---

# dcg-safe

Run `dcg-safe config check` to see the normalized capture roots. Select three
new absolute file paths beneath available roots and invoke:

```text
dcg-safe capture \
  --stdout /absolute/path/stdout.txt \
  --stderr /absolute/path/stderr.txt \
  --status /absolute/path/status.txt \
  -- command arg...
```

Only a status file containing exactly one newline-terminated integer is a
complete outcome record. Wrapper diagnostics remain on the invoking terminal's
stderr.

dcg-safe limits only where capture files are created. It does not sandbox the
child command, change DCG policy, or authorize a command that DCG denies.
