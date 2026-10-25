package automation

import (
	"context"
	"fmt"
	"time"
)

// defaultCallTimeout bounds each voter RPC of an ordinary automation decision.
const defaultCallTimeout = 750 * time.Millisecond

// generationBarrierAcceptTimeout bounds each phase-2 (Accept) RPC of a
// generation barrier; phase 1 keeps defaultCallTimeout, which a quorum meets.
// The proposer waits for every voter in phase 2, so a voter that is always
// slower than defaultCallTimeout, but alive, signs the barrier. The caller
// probes that a missing voter is alive first, so a dead one never costs this.
const generationBarrierAcceptTimeout = 10 * time.Second

type acceptTimeoutKey struct{}

func withAcceptTimeout(ctx context.Context, d time.Duration) context.Context {
	return context.WithValue(ctx, acceptTimeoutKey{}, d)
}

func acceptTimeout(ctx context.Context) time.Duration {
	if d, ok := ctx.Value(acceptTimeoutKey{}).(time.Duration); ok && d > 0 {
		return d
	}
	return defaultCallTimeout
}

// GenerationBarrier certifies an internal read barrier at voter generation
// gen, this voter's adopted one, so the generation carries certified evidence
// of which voters hold automation authority there without any user command
// (F1 Task 5G follow-up B). The request id names this voter, gen and the
// caller's tag (a per-process nonce and attempt); skip names voters phase 2
// is not sent to because the caller found them unreachable: request ids are not scoped by principal, so two voters must not
// share one, and a retry is a new barrier, not the original request. It
// needs this voter's authority at gen and an initialized automation history.
func (e *Engine) GenerationBarrier(ctx context.Context, gen int64, tag string, skip []string) error {
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
		RequestID: fmt.Sprintf("voter-generation-barrier-%s-%d-%s", e.self, gen, tag), Body: []byte(`{"version":1}`)}
	_, err = e.Submit(withAcceptSkip(withAcceptTimeout(ctx, generationBarrierAcceptTimeout), skip), c)
	return err
}

type acceptSkipKey struct{}

// withAcceptSkip names voters a generation barrier does not send phase 2 to:
// ones its caller just found unreachable. The certificate still needs a
// majority of the whole electorate, so skipping an acceptor only means fewer
// accepts; it never lets a smaller quorum decide.
func withAcceptSkip(ctx context.Context, skip []string) context.Context {
	if len(skip) == 0 {
		return ctx
	}
	return context.WithValue(ctx, acceptSkipKey{}, append([]string(nil), skip...))
}

func acceptSkip(ctx context.Context) map[string]bool {
	names, _ := ctx.Value(acceptSkipKey{}).([]string)
	if len(names) == 0 {
		return nil
	}
	out := make(map[string]bool, len(names))
	for _, n := range names {
		out[n] = true
	}
	return out
}
