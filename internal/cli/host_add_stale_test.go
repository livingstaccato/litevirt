package cli

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// fixAddClock makes addNow return now for the test.
func fixAddClock(t *testing.T, now time.Time) {
	t.Helper()
	old := addNow
	addNow = func() time.Time { return now }
	t.Cleanup(func() { addNow = old })
}

// otherAdmissionsInstall puts another admission's install on f's machine: a
// certificate of this cluster's CA for node-x, not revoked, and an install
// record of it dated at. It returns the certificate's serial and bytes.
func otherAdmissionsInstall(t *testing.T, f *addFixture, at time.Time) (string, []byte) {
	t.Helper()
	x := installPair(t, f, f.opPKI, "node-x")
	writeMarker(t, f.target, fmt.Sprintf("node-x %s %d cafecafe0000 installed\n", x, at.Unix()))
	return x, mustRead(t, filepath.Join(f.targetPKI, "host.crt"))
}

// The user's ruling: a fresh `lv host add` may replace a stale install. Over
// another admission's install that is not a live member and whose
// certificate this cluster has not revoked, the add installs when that
// install is freshInstall old or older, and installs nothing (nor stops the
// daemon) when it is younger. The boundary is freshInstall exactly.
//
// Mutations: drop the age term from refuseSecondInstall — "over an hour" and
// "exactly an hour" are refused; invert it (<) — every case flips; make it
// strict (>) — "exactly an hour" is refused.
func TestHostAdd_AFreshAddReplacesOnlyAStaleInstall(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for _, tc := range []struct {
		name     string
		age      time.Duration
		replaces bool
	}{
		{"over an hour", 2 * time.Hour, true},
		{"exactly an hour", freshInstall, true},
		{"a second under an hour", freshInstall - time.Second, false},
		{"under an hour", 10 * time.Minute, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixAddClock(t, now)
			f := newAddFixture(t)
			x, xBytes := otherAdmissionsInstall(t, f, now.Add(-tc.age))
			err := f.add(t)
			if tc.replaces {
				if err != nil {
					t.Fatalf("add over a %v-old install: %v", tc.age, err)
				}
				servesItsAdmittedPair(t, f.targetPKI, f.client.admitted[0])
				return
			}
			if err == nil || !strings.Contains(err.Error(), x) || !strings.Contains(err.Error(), "installs nothing") {
				t.Fatalf("add over a %v-old install = %v, want refused naming %s", tc.age, err, x)
			}
			if reachedInstall(f.target.Events) {
				t.Errorf("stopped the daemon or installed over a recent install: %v", f.target.Events)
			}
			if !bytes.Equal(mustRead(t, filepath.Join(f.targetPKI, "host.crt")), xBytes) {
				t.Error("the other admission's certificate was replaced")
			}
		})
	}
}

// A live member's install is never replaced, whatever its install record's
// age or whether there is one: the add refuses before it admits, stages,
// stops or installs anything.
//
// Mutation: make refuseAnotherMember return nil — the stale and unrecorded
// cases install over the member's identity.
func TestHostAdd_AFreshAddNeverReplacesALiveMember(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for _, tc := range []struct {
		name   string
		member func(serial string) *pb.Host
		age    time.Duration // 0: no install record
	}{
		{"its certificate, installed over an hour ago", func(s string) *pb.Host {
			return &pb.Host{Name: "node-x", Address: "10.0.0.5", State: pb.HostState_HOST_ACTIVE, CertSerial: s}
		}, 2 * time.Hour},
		{"its certificate, installed a day ago", func(s string) *pb.Host {
			return &pb.Host{Name: "node-x", Address: "10.0.0.5", State: pb.HostState_HOST_ACTIVE, CertSerial: s}
		}, 24 * time.Hour},
		{"its certificate, installed minutes ago", func(s string) *pb.Host {
			return &pb.Host{Name: "node-x", Address: "10.0.0.5", State: pb.HostState_HOST_ACTIVE, CertSerial: s}
		}, 5 * time.Minute},
		{"its certificate, no install record", func(s string) *pb.Host {
			return &pb.Host{Name: "node-x", Address: "10.0.0.5", State: pb.HostState_HOST_ACTIVE, CertSerial: s}
		}, 0},
		{"its address, installed over an hour ago", func(string) *pb.Host {
			return &pb.Host{Name: "node-x", Address: "10.0.0.9", State: pb.HostState_HOST_ACTIVE, CertSerial: "ffff"}
		}, 2 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixAddClock(t, now)
			f := newAddFixture(t)
			x := installPair(t, f, f.opPKI, "node-x")
			if tc.age != 0 {
				writeMarker(t, f.target, fmt.Sprintf("node-x %s %d cafecafe0000 installed\n", x, now.Add(-tc.age).Unix()))
			}
			xBytes := mustRead(t, filepath.Join(f.targetPKI, "host.crt"))
			f.client.hosts = append(f.client.hosts, tc.member(x))
			err := f.add(t)
			if err == nil || !strings.Contains(err.Error(), "refusing to add node-9") {
				t.Fatalf("add over live member node-x = %v, want refused", err)
			}
			if len(f.client.admitted) != 0 || reachedInstall(f.target.Events) || len(f.staged(t)) != 0 {
				t.Errorf("admitted %v, staged %v, events %v: want nothing", f.client.admitted, f.staged(t), f.target.Events)
			}
			if !bytes.Equal(mustRead(t, filepath.Join(f.targetPKI, "host.crt")), xBytes) {
				t.Error("the live member's certificate was replaced")
			}
		})
	}
}
