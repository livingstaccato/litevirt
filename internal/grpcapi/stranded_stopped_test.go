package grpcapi

import (
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// `lv host rm --dead`'s plan lists each stopped VM failover leaves on the
// host with what happens to it: one with a host-local disk stays recorded
// there (and comes back with the machine); one stopped on purpose on shared
// storage may still be moved, stopped. Neither is counted as a recovery
// that will retry.
func TestStrandedOn_ListsStoppedVMsWithTheirFate(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	for _, v := range []struct {
		name, storage string
	}{{"st-local", "local"}, {"st-shared", "nfs"}} {
		if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
			Name: v.name, HostName: "gone", State: "stopped", StateDetail: "operator-stop",
			Spec: `{"on_host_failure":"restart-any"}`,
		}, nil, []corrosion.DiskRecord{{VMName: v.name, DiskName: "root", HostName: "gone",
			Path: "/d/" + v.name, StorageType: v.storage}}); err != nil {
			t.Fatal(err)
		}
	}
	out, err := s.strandedOn(ctx, "gone")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, st := range out {
		if st.NextAttempt != 0 {
			t.Errorf("%s/%s is counted as a recovery that retries (attempt %d)", st.Kind, st.Name, st.NextAttempt)
		}
		got[st.Name] = st.Detail
	}
	if d := got["st-local"]; !strings.Contains(d, "is stopped") || !strings.Contains(d, "not moved by this removal") {
		t.Errorf("st-local plan line = %q", d)
	}
	if d := got["st-shared"]; !strings.Contains(d, "on shared storage") || !strings.Contains(d, "still stopped") {
		t.Errorf("st-shared plan line = %q", d)
	}
}
