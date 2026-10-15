package firewall

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/litevirt/litevirt/internal/cmdbound"
)

// Kernel feature probe. A ruleset feature the running kernel or nft may not
// support (a per-source meter, a log statement) is tried with `nft -c -f -`
// before the renderer relies on it: check only, nothing is committed, so a
// refusal costs nothing and the live tables are untouched.

// probeRunner runs nft with args and stdin, returning its combined output.
// Tests replace it.
var probeRunner = func(ctx context.Context, stdin string, args ...string) (string, error) {
	cmd := cmdbound.Command(ctx, "nft", args...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmdbound.CombinedOutput(ctx, cmd)
	return string(out), err
}

// ProbeTableName is the scratch table a probe declares, unique per process.
func ProbeTableName() string {
	return fmt.Sprintf("lv_probe_%d", os.Getpid())
}

// ProbeRuleset reports whether the kernel accepts body as the contents of a
// bridge table, without loading it: it runs `nft -c -f -` over
// `table bridge lv_probe_<pid> { <body> }`. A refusal is returned with nft's
// output.
func ProbeRuleset(ctx context.Context, body string) error {
	table := ProbeTableName()
	ruleset := fmt.Sprintf("table bridge %s {\n%s\n}\n", table, body)
	out, err := probeRunner(ctx, ruleset, "-c", "-f", "-")
	if err != nil {
		return fmt.Errorf("nft refused probe table %s: %w: %s", table, err, strings.TrimSpace(out))
	}
	return nil
}
