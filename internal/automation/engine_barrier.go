package automation

import (
	"context"
	"fmt"
	"time"
)

// defaultCallTimeout bounds each voter RPC of an ordinary automation decision.
const defaultCallTimeout = 750 * time.Millisecond

// generationBarrierCallTimeout bounds each voter RPC of a generation barrier.
// The proposer already waits for every voter in phase 2; this lets a voter
// that is always slower than defaultCallTimeout, but alive, sign it.
const generationBarrierCallTimeout = 10 * time.Second

type callTimeoutKey struct{}

func withCallTimeout(ctx context.Context, d time.Duration) context.Context {
	return context.WithValue(ctx, callTimeoutKey{}, d)
}

func callTimeout(ctx context.Context) time.Duration {
	if d, ok := ctx.Value(callTimeoutKey{}).(time.Duration); ok && d > 0 {
		return d
	}
	return defaultCallTimeout
}

// GenerationBarrier certifies an internal read barrier at voter generation
// gen, this voter's adopted one, so the generation carries certified evidence
// of which voters hold automation authority there without any user command
// (F1 Task 5G follow-up B). The request id names this voter, gen and
// attempt: request ids are not scoped by principal, so two voters must not
// share one, and a retry is a new barrier, not the original request. It
// needs this voter's authority at gen and an initialized automation history.
func (e *Engine) GenerationBarrier(ctx context.Context, gen int64, attempt int) error {
	cfg, err := e.db.AutomationMembership(ctx)
	if err != nil {
		return err
	}
	if cfg.Generation != gen {
		return fail(CodeUnavailable)
	}
	h, err := e.db.AutomationHead(ctx)
	if err != nil {
		return err
	}
	if h.Sequence == 0 {
		return fail(CodeUnavailable)
	}
	c := Command{Kind: "read_barrier", ClusterUID: h.ClusterUID, PrincipalID: e.self,
		RequestID: fmt.Sprintf("voter-generation-barrier-%s-%d-%d", e.self, gen, attempt), Body: []byte(`{"version":1}`)}
	_, err = e.Submit(withCallTimeout(ctx, generationBarrierCallTimeout), c)
	return err
}
