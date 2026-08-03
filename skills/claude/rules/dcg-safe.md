# dcg-safe capture rule

Use the dcg-safe skill when command stdout, stderr, and exit status must be
captured beneath configured roots and shell redirection would trigger DCG. Do
not use it to bypass a DCG denial of the child command.

dcg-safe v0.2.0 requires DCG 0.9.2 or newer installed as an executable named
`dcg` beside the canonical `dcg-safe` binary. It checks the child command with
that co-located DCG before reserving capture files. On denial or evaluator
failure it exits 125, starts no child, and leaves capture files absent.
