package main

import (
	"testing"

	"github.com/litevirt/litevirt/internal/storage"
	"github.com/litevirt/litevirt/tests/e2e/pitprobe"
)

// The point-in-time e2e creates its dir pools with pitprobe's argv. It
// shipped `--source <dir>`, which the daemon refuses for a dir pool since
// 934c3222 (lab 2 run c2, defect 1). Parsed by the real command, the argv
// must set only flags the command has, and pass the storage rule a create
// is judged by.
//
// Mutation "the e2e names --source again" — red.
func TestPITE2E_DirPoolArgsParse(t *testing.T) {
	const dir = "/var/lib/litevirt/pools/pitsrc-x"
	args := pitprobe.DirPoolCreateArgs("pitsrc-x", dir, "node-1")
	cmd, rest, err := newRootCmd().Find(args)
	if err != nil || cmd.Name() != "create" || cmd.Parent().Name() != "pool" {
		t.Fatalf("`lv %v` does not resolve to pool create: %v", args, err)
	}
	if err := cmd.ParseFlags(rest); err != nil {
		t.Fatalf("`lv %v`: %v", args, err)
	}
	get := func(f string) string { return cmd.Flags().Lookup(f).Value.String() }
	cfg := storage.Config{Driver: get("driver"), Source: get("source")}
	if err := storage.ValidateSource(cfg); err != nil {
		t.Fatalf("`lv %v` is refused: %v", args, err)
	}
	if get("target") != dir {
		t.Fatalf("`lv %v` does not root the pool at %s (--target %q)", args, dir, get("target"))
	}
}
