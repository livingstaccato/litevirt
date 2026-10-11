package firewall

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

// TestReconciler_PassHookTracksEnforcement (re-review m5): every pass tells
// the pass hook whether the per-NIC table is in force after it: a good pass
// says so; a refused table, a failed load and a failed apply do not.
func TestReconciler_PassHookTracksEnforcement(t *testing.T) {
	loadErr := error(nil)
	loader := func(context.Context) (Plan, error) {
		return Plan{NICs: []NICBinding{{NICDev: "vnet1", Bridge: "br0"}}}, loadErr
	}
	nft := &bridgeRefusingNft{}
	refuse := false
	var got []bool
	r := NewReconciler(loader, NewApplier(&switchNft{refuse: &refuse, ok: &nft.fakeNft, bad: nft}), 0)
	r.SetPassHook(func(_ context.Context, enforcing bool) { got = append(got, enforcing) })
	_ = r.Reconcile(context.Background())
	refuse = true
	r.applier.Reset()
	_ = r.Reconcile(context.Background())
	refuse = false
	loadErr = errors.New("corrosion unreachable")
	_ = r.Reconcile(context.Background())
	loadErr = nil
	r.applier.Reset()
	_ = r.Reconcile(context.Background())
	if want := []bool{true, false, false, true}; !reflect.DeepEqual(got, want) {
		t.Errorf("pass hook saw %v, want %v (ok, refused, load failed, ok)", got, want)
	}
}

// switchNft refuses the per-NIC table while *refuse.
type switchNft struct {
	refuse *bool
	ok     *fakeNft
	bad    *bridgeRefusingNft
}

func (s *switchNft) Apply(ctx context.Context, ruleset string) (string, error) {
	if *s.refuse {
		return s.bad.Apply(ctx, ruleset)
	}
	return s.ok.Apply(ctx, ruleset)
}

func (s *switchNft) Flush(ctx context.Context) (string, error) { return s.ok.Flush(ctx) }
