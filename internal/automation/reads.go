package automation

import (
	"context"
	"errors"
	"math"
	"strings"
	"unicode/utf8"

	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/corrosion"
)

var errAbsent = errors.New("automation: authoritatively absent")

func IsAbsent(err error) bool                   { return errors.Is(err, errAbsent) }
func contractEncode(d Decision) ([]byte, error) { return contract.EncodeDecision(d) }
func contractDecode(v corrosion.ClaimValue) (Decision, error) {
	if v.Automation == nil {
		return Decision{}, fail(CodeValidation)
	}
	return contract.DecodeDecision(v.Automation.Envelope)
}
func (e *Engine) barrier(ctx context.Context, min uint64) error {
	_, err := e.readBarrier(ctx, min)
	return err
}
func (e *Engine) readBarrier(ctx context.Context, min uint64) (corrosion.AutomationPrefix, error) {
	if min > math.MaxInt64 {
		return corrosion.AutomationPrefix{}, fail(CodeValidation)
	}
	if err := e.recover(ctx); err != nil {
		return corrosion.AutomationPrefix{}, fail(CodeUnavailable)
	}
	h, err := e.db.AutomationHead(ctx)
	if err != nil {
		return corrosion.AutomationPrefix{}, err
	}
	if h.Sequence == 0 || min > h.Sequence+128 {
		return corrosion.AutomationPrefix{}, fail(CodeUnavailable)
	}
	r, err := e.submit(ctx, Command{Kind: "read_barrier", ClusterUID: h.ClusterUID, PrincipalID: e.self, RequestID: randomID(), Body: []byte(`{"version":1}`)})
	if err != nil {
		return corrosion.AutomationPrefix{}, err
	}
	if r.Sequence < min {
		return corrosion.AutomationPrefix{}, fail(CodeUnavailable)
	}
	return corrosion.AutomationPrefix{ClusterUID: h.ClusterUID, Sequence: r.Sequence}, nil
}
func (e *Engine) Observe(ctx context.Context, uid string, min uint64) (View, error) {
	if uid == "" || len(uid) > contract.MaxStringBytes || !utf8.ValidString(uid) || strings.IndexByte(uid, 0) >= 0 || min > math.MaxInt64 {
		return View{}, fail(CodeValidation)
	}
	if err := e.enter(ctx); err != nil {
		return View{}, err
	}
	defer e.leave()
	barrier, err := e.readBarrier(ctx, min)
	if err != nil {
		return View{}, err
	}
	view, found, err := e.db.AutomationObserve(ctx, barrier.ClusterUID, uid, barrier.Sequence)
	if err != nil {
		return View{}, err
	}
	if !found {
		return View{}, errAbsent
	}
	return view, nil
}
func (e *Engine) Operation(ctx context.Context, id string) (Receipt, error) {
	if err := e.enter(ctx); err != nil {
		return Receipt{}, err
	}
	defer e.leave()
	if err := e.barrier(ctx, 0); err != nil {
		return Receipt{}, err
	}
	r, ok, err := e.db.AutomationOperation(ctx, id)
	if err != nil {
		return Receipt{}, err
	}
	if !ok {
		return Receipt{}, errAbsent
	}
	return r, nil
}
