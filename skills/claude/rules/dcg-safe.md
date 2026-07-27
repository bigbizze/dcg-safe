# dcg-safe capture rule

Use the dcg-safe skill when command stdout, stderr, and exit status must be
captured beneath configured roots and shell redirection would trigger DCG. Do
not use it to bypass a DCG denial of the child command.
