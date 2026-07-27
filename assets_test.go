package dcgsafe

import (
	"os"
	"testing"
)

func TestEmbeddedAssetsMatchAuditableFiles(t *testing.T) {
	tests := []struct {
		path     string
		embedded string
	}{
		{path: "config.example.toml", embedded: DefaultConfig},
		{path: "skills/codex/dcg-safe/SKILL.md", embedded: CodexSkill},
		{path: "skills/codex/dcg-safe/agents/openai.yaml", embedded: CodexMetadata},
		{path: "skills/claude/dcg-safe/SKILL.md", embedded: ClaudeSkill},
		{path: "skills/claude/rules/dcg-safe.md", embedded: ClaudeRule},
	}
	for _, test := range tests {
		body, err := os.ReadFile(test.path)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != test.embedded {
			t.Fatalf("embedded bytes differ from %s", test.path)
		}
	}
}
