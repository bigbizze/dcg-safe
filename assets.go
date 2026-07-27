// Package dcgsafe exposes the exact release assets embedded in the dcg-safe
// binary. Keeping these files in one package ensures runtime defaults,
// delegated installs, and release archives all use identical bytes.
package dcgsafe

import _ "embed"

// DefaultConfig is both the runtime fallback and the source written by
// `dcg-safe config init`.
//
//go:embed config.example.toml
var DefaultConfig string

//go:embed skills/codex/dcg-safe/SKILL.md
var CodexSkill string

//go:embed skills/codex/dcg-safe/agents/openai.yaml
var CodexMetadata string

//go:embed skills/claude/dcg-safe/SKILL.md
var ClaudeSkill string

//go:embed skills/claude/rules/dcg-safe.md
var ClaudeRule string
