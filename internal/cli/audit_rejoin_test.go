package cli

import (
	"encoding/json"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// TestAuditRejoinFile_KeepsARecordOnAnUnvouchedNoHistory: a daemon too old to
// vouch for a position answers seq 0 for every name. Removing a record already
// on the machine on that word would let a rebuilt host fork, so only a vouched
// "no history" removes one. A position is signed for the certificate minted
// for this machine.
//
// Mutation: remove on any seq-0 answer — the unvouched case says remove.
func TestAuditRejoinFile_KeepsARecordOnAnUnvouchedNoHistory(t *testing.T) {
	dir := t.TempDir()
	if err := pki.GenerateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		proven     bool
		wantRemove bool
	}{{false, false}, {true, true}} {
		rec, remove, err := AuditRejoinFile(dir, "node-4", "0a0b", &pb.AdmitHostResponse{AuditPositionProven: tc.proven})
		if err != nil || rec != nil || remove != tc.wantRemove {
			t.Errorf("seq 0, proven=%v: record=%v remove=%v err=%v; want remove=%v",
				tc.proven, rec != nil, remove, err, tc.wantRemove)
		}
	}
	rec, remove, err := AuditRejoinFile(dir, "node-4", "0a0b",
		&pb.AdmitHostResponse{AuditTailSeq: 12, AuditTailHash: "ab", AuditPositionProven: true})
	if err != nil || remove || rec == nil {
		t.Fatalf("seq 12: record=%v remove=%v err=%v", rec != nil, remove, err)
	}
	var rj corrosion.AuditRejoin
	if err := json.Unmarshal(rec, &rj); err != nil || rj.Seq != 12 || rj.CertSerial != "0a0b" || rj.Host != "node-4" {
		t.Fatalf("record %+v (%v)", rj, err)
	}
}
