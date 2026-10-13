package cmdbound

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Round 3 (lab 2 N-3): Output returns stdout only, on the ErrWaitDelay
// success path too — a banner on stderr (cephadm's) never reaches a caller
// that parses stdout.
//
// Mutation "Output captures stderr into stdout" — red.
func TestOutput_StderrStaysOutOfStdoutWhenAChildHoldsThePipe(t *testing.T) {
	prev := WaitDelay
	WaitDelay = 300 * time.Millisecond
	t.Cleanup(func() { WaitDelay = prev })
	ctx := context.Background()
	out, err := Output(ctx, Command(ctx, "sh", "-c", `echo "Inferring fsid abc" >&2; sleep 5 & echo '{"ok":1}'`))
	if err != nil || strings.TrimSpace(string(out)) != `{"ok":1}` {
		t.Fatalf("Output with a banner on stderr and a child holding the pipes = %q, %v; want the JSON alone", out, err)
	}
}
