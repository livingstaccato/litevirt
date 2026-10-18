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

// Lab recheck3 anomaly 3: `lv host rm --dead` said a Secure Boot / vTPM VM
// would be "recovered at its current claim attempt", while failover never
// recovers one (its firmware state died with the host) and logged that it
// skipped it every pass. The plan now says so, names what the operator can
// do, and does not count it as a recovery that will retry.
//
// Mutation: drop the firmware case — the line promises a recovery.
func TestStrandedOn_AFirmwareVMIsNotPromisedARecovery(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	for name, spec := range map[string]string{
		"fw-sb":  `{"on_host_failure":"restart-any","secure_boot":true}`,
		"fw-tpm": `{"on_host_failure":"restart-any","tpm":true}`,
		"plain":  `{"on_host_failure":"restart-any"}`,
	} {
		if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
			Name: name, HostName: "gone", State: "running", Spec: spec,
		}, nil, []corrosion.DiskRecord{{VMName: name, DiskName: "root", HostName: "gone",
			Path: "/d/" + name, StorageType: "nfs"}}); err != nil {
			t.Fatal(err)
		}
	}
	out, err := s.strandedOn(ctx, "gone")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, st := range out {
		got[st.Name] = st.Detail
		if strings.HasPrefix(st.Name, "fw-") && st.NextAttempt != 0 {
			t.Errorf("%s is counted as a recovery that retries", st.Name)
		}
	}
	for _, n := range []string{"fw-sb", "fw-tpm"} {
		d := got[n]
		// fd re-review N-I3: restore-from writes a bare disk and no firmware;
		// restore-live --auto-start brings the NVRAM and TPM back.
		if strings.Contains(d, "recovered at") || !strings.Contains(d, "never recovers") ||
			!strings.Contains(d, "lv backup restore-live") || !strings.Contains(d, "--auto-start") ||
			strings.Contains(d, "restore-from") {
			t.Errorf("%s plan line = %q; want no promised recovery and the restore command", n, d)
		}
	}
	if d := got["plain"]; !strings.Contains(d, "recovered at its current claim attempt") {
		t.Errorf("plain plan line = %q", d)
	}
}
