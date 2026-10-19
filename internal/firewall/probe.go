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

// ProbeLogging reports whether the kernel and nft load the renderer's
// logging forms (spec §3.4): a named limit, declared as the renderer declares
// one, and a log line sending to NFLOG group, as the renderer writes it. A
// host that refuses them renders no log line and raises
// firewall.log.unavailable rather than lose its per-NIC table.
func ProbeLogging(ctx context.Context, group uint16) error {
	const limit = "lv_lg_probe"
	var b strings.Builder
	renderLogLimit(&b, limit, LogPolicy{})
	b.WriteString("    chain probe {\n        type filter hook forward priority 0; policy accept;\n")
	b.WriteString("        meta l4proto tcp " + logStmt(LogPolicy{Group: group}, limit, logPrefix("lvprobe", "in", "default", "drop")) + "\n")
	b.WriteString("    }")
	return ProbeRuleset(ctx, b.String())
}
