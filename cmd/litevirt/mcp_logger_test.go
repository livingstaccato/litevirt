package main

import (
	"bytes"
	"strings"
	"testing"
)

// The MCP server's logger masks a secret-bearing attribute like every other
// entrypoint's.
func TestMCPLogger_MasksSecretKeys(t *testing.T) {
	var b bytes.Buffer
	newMCPLogger(&b).Info("probe", "token", "mcp-secret-7d1", "vm", "web")
	out := b.String()
	if strings.Contains(out, "mcp-secret-7d1") {
		t.Fatalf("mcp logger wrote the token in clear: %q", out)
	}
	if !strings.Contains(out, "vm=web") {
		t.Fatalf("mcp logger dropped a plain attribute: %q", out)
	}
}
