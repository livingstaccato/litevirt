package netboxsync

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netbox"
)

// A delete refused because an address on the object could not be detached —
// the API token may view it but not change it — is withheld, for that one
// object only. The rest of the pass runs; the mapping is kept, since nothing
// was removed; and the pass names the address so the operator can fix the
// token's permissions.

func TestApplyWithholdsADeleteBlockedByAnAddressItCannotChange(t *testing.T) {
	nb := &stubVirt{deleteErr: &netbox.AddressNotChangeableError{ID: 900, Address: "192.0.2.9/32", AssignedTo: 21}}
	r := newTestReconciler(t, nb)
	key := nicIdent("u1", "52:54:00:00:00:01")
	ctx := context.Background()
	if err := corrosion.PutObjectRef(ctx, r.db, corrosion.ObjectRef{
		LitevirtKind: kindNIC, LitevirtKey: key, NetBoxKind: netboxKindNIC, NetBoxID: 21,
	}); err != nil {
		t.Fatal(err)
	}
	if err := r.apply(ctx, []Action{{Kind: kindNIC, Op: "delete", Key: key, NetBoxID: 21}},
		indexDesired(nil, fp), fp); err != nil {
		t.Fatalf("one blocked delete failed the phase: %v", err)
	}
	if ref := mustGetRef(t, r, kindNIC, key); ref.NetBoxID != 21 {
		t.Fatalf("mapping = %+v, want it kept: nothing was removed", ref)
	}
	blocked := r.blockedRemovals()
	if detail, ok := blocked["900"]; !ok || detail == "" {
		t.Fatalf("blocked = %v, want address 900 named", blocked)
	}
}

func TestApplyStillFailsOnAnyOtherDeleteError(t *testing.T) {
	nb := &stubVirt{deleteErr: &netbox.APIError{Status: 500, Body: "boom"}}
	r := newTestReconciler(t, nb)
	if err := r.apply(context.Background(),
		[]Action{{Kind: kindNIC, Op: "delete", Key: nicIdent("u1", "52:54:00:00:00:01"), NetBoxID: 21}},
		indexDesired(nil, fp), fp); err == nil {
		t.Fatal("a 500 on a delete was withheld like a permission refusal")
	}
	if len(r.blockedRemovals()) != 0 {
		t.Fatalf("blocked = %v after a 500", r.blockedRemovals())
	}
}
