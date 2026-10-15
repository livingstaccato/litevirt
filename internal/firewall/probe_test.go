package firewall

import (
	"context"
	"errors"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// ProbeRuleset only checks: it runs nft with -c over a scratch bridge table
// named for this process, holding the body, and returns a refusal.
//
// Mutations: drop -c (the probe would commit the table) — red; ignore the
// runner's error — red; name a fixed table — red.
func TestProbeRuleset_ChecksOnlyAndReturnsRefusal(t *testing.T) {
	prev := probeRunner
	t.Cleanup(func() { probeRunner = prev })
	var gotArgs []string
	var gotStdin string
	refuse := false
	probeRunner = func(_ context.Context, stdin string, args ...string) (string, error) {
		gotArgs, gotStdin = args, stdin
		if refuse {
			return "Error: syntax error, unexpected meter", errors.New("exit status 1")
		}
		return "", nil
	}
	body := "\tchain c {\n\t\tcounter\n\t}"
	if err := ProbeRuleset(context.Background(), body); err != nil {
		t.Fatalf("an accepted probe: %v", err)
	}
	if !slices.Equal(gotArgs, []string{"-c", "-f", "-"}) {
		t.Errorf("nft args = %v, want -c -f - (check only)", gotArgs)
	}
	table := ProbeTableName()
	if want := "lv_probe_" + strconv.Itoa(os.Getpid()); table != want {
		t.Errorf("probe table = %q, want %q", table, want)
	}
	if !strings.HasPrefix(gotStdin, "table bridge "+table+" {\n") || !strings.Contains(gotStdin, body) {
		t.Errorf("probe input = %q, want the body inside table bridge %s", gotStdin, table)
	}
	refuse = true
	err := ProbeRuleset(context.Background(), body)
	if err == nil || !strings.Contains(err.Error(), "unexpected meter") {
		t.Errorf("a refused probe = %v, want the refusal with nft's output", err)
	}
}
