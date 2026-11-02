# dcg-safe capture rule

Use the dcg-safe skill when command stdout, stderr, and exit status must be
captured beneath configured roots and shell redirection would trigger DCG. Do
not use it to bypass a DCG denial of the child command.

dcg-safe v0.2.1 requires DCG 0.16.0 or newer installed as an executable named
`dcg` beside the canonical `dcg-safe` binary. It checks the child command with
that co-located DCG before reserving capture files. On denial, evaluator
failure, or a DCG configuration error it exits 125, starts no child, and leaves
capture files absent. Do not bypass a DCG configuration error; repair the DCG
configuration and run `dcg doctor --strict`.
