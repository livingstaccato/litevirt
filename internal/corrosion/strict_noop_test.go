package corrosion

import (
	"context"
	"errors"
	"testing"
)

// A strict write whose zero-row result the caller treats as "did not happen"
// must not happen anywhere else either.
//
// mutation_log carries statements, so a zero-row UPDATE that is relayed is
// REPLAYED by every peer — and a peer that holds the row (or holds it at a state
// the local guard has already moved past) applies a change the caller was told
// failed. parked_updates.go then closes the loop on the origin itself: an update
// that met no row is replayed here once the row arrives. So a failed
// UpdateDiskPlacement used to move the disk's recorded placement on every node,
// including, eventually, the one that reported the failure.
//
// These helpers all return a refusal (ErrNoRowsAffected, a false "applied", or a
// helper-specific error) on zero rows, and every caller treats that as refused /
// retry. None of them may queue a relay or park an update for a refused write.
func TestStrictHelpers_AZeroRowRefusalIsNeitherRelayedNorParked(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		run  func(c *Client) error // nil means "refused as the helper's contract says"
	}{
		{"UpdateVMStateStrict", func(c *Client) error {
			return wantErr(UpdateVMStateStrict(ctx, c, "no-vm", "running", ""), ErrNoRowsAffected)
		}},
		{"UpdateDiskPlacement", func(c *Client) error {
			return wantErr(UpdateDiskPlacement(ctx, c, "no-vm", "vda", "h", "/p", "dir", "pool"), ErrNoRowsAffected)
		}},
		{"SetContainerStateStrict", func(c *Client) error {
			return wantErr(SetContainerStateStrict(ctx, c, "h", "no-ct", "running"), ErrNoRowsAffected)
		}},
		{"SetContainerStateDetailStrict", func(c *Client) error {
			return wantErr(SetContainerStateDetailStrict(ctx, c, "h", "no-ct", "running", ""), ErrNoRowsAffected)
		}},
		{"SetContainerStateDetailStrictAtEpoch", func(c *Client) error {
			return wantErr(SetContainerStateDetailStrictAtEpoch(ctx, c, "h", "no-ct", "running", "", 3), ErrNoRowsAffected)
		}},
		{"GraduateVMOwnerEpoch", func(c *Client) error {
			return wantErr(GraduateVMOwnerEpoch(ctx, c, "no-vm"), ErrNoRowsAffected)
		}},
		{"IsolateHost", func(c *Client) error {
			return wantErr(IsolateHost(ctx, c, "n2", "no-host", IsolationManual), ErrIsolationNotMonotone)
		}},
		{"ClearHostIsolation", func(c *Client) error {
			return wantErr(ClearHostIsolation(ctx, c, "no-host", 1), ErrNoRowsAffected)
		}},
		{"SetHostNetworkState", func(c *Client) error {
			return wantErr(SetHostNetworkState(ctx, c, "h", "no-net", HostNetworkApplying, ""), ErrNoRowsAffected)
		}},
		{"MarkHostNetworkApplied", func(c *Client) error {
			return wantErr(MarkHostNetworkApplied(ctx, c, "h", "no-net"), ErrNoRowsAffected)
		}},
		{"DeleteHostNetwork", func(c *Client) error {
			return wantErr(DeleteHostNetwork(ctx, c, "h", "no-net"), ErrNoRowsAffected)
		}},
		{"UpsertBinding", func(c *Client) error {
			if err := UpsertBinding(ctx, c, BindingRecord{PrefixID: 7, Network: "n"}); err == nil {
				return errors.New("UpsertBinding of a missing binding succeeded")
			}
			return nil
		}},
		{"UpdateObservedActuals", func(c *Client) error {
			return wantFalse(UpdateObservedActuals(ctx, c, "no-vm", 2, 2048, 1, 1))
		}},
		{"TouchUser2FA", func(c *Client) error {
			return wantFalse(TouchUser2FA(ctx, c, "u", "webauthn", "key"))
		}},
		{"RecordTOTPStep", func(c *Client) error {
			return wantFalse(RecordTOTPStep(ctx, c, "u", "totp", "", "secret", 99))
		}},
		{"MarkRecoveryCodeUsed", func(c *Client) error {
			return wantFalse(MarkRecoveryCodeUsed(ctx, c, "u", "hash"))
		}},
		{"ClaimPCIDevice", func(c *Client) error {
			return wantFalse(ClaimPCIDevice(ctx, c, "h", "0000:00:01.0", "vm"))
		}},
		{"ClaimLBHolderIfUnowned", func(c *Client) error {
			return wantFalse(ClaimLBHolderIfUnowned(ctx, c, "no-lb", `["h"]`))
		}},
		{"CompleteActionProof", func(c *Client) error {
			return wantErr(CompleteActionProof(ctx, c, "no-proof", "h"), ErrNoRowsAffected)
		}},
		{"ClaimActionProof (unfenced)", func(c *Client) error {
			return wantErr(ClaimActionProofFenced(ctx, c, "no-proof", "h", nil), ErrProofSpent)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := testClient(t)
			before := mutationLogCount(t, c)
			if err := tc.run(c); err != nil {
				t.Fatalf("premise: %v", err)
			}
			if after := mutationLogCount(t, c); after != before {
				t.Errorf("a refused %s queued %d statement(s) for replication: every peer that "+
					"holds the row applies a write the caller was told did not happen", tc.name, after-before)
			}
			if got := c.ParkedUpdates(); got != 0 {
				t.Errorf("a refused %s parked %d update(s): the origin would apply its own "+
					"refused write once the row arrives", tc.name, got)
			}
		})
	}
}

// The row is HERE but the strict write's own guard declined it. Relaying it
// hands the same guarded statement to peers whose copy is behind — and they
// match. A tombstoned disk is the placement case: a peer that has not yet seen
// the tombstone would repoint a disk the origin already retired.
func TestUpdateDiskPlacement_AGuardMissOnAPresentRowIsNotRelayed(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	if err := InsertVM(ctx, c, VMRecord{Name: "vm1", HostName: "h", Spec: "{}", State: "stopped"}, nil,
		[]DiskRecord{{VMName: "vm1", DiskName: "vda", HostName: "h", Path: "/old", StorageType: "dir", StorageVolume: "p1"}}); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := c.Execute(ctx, `UPDATE vm_disks SET deleted_at = ?, updated_at = ? WHERE vm_name = ? AND disk_name = ?`,
		nowRFC3339(), c.NowTS(), "vm1", "vda"); err != nil {
		t.Fatalf("tombstone disk: %v", err)
	}
	before := mutationLogCount(t, c)
	if err := UpdateDiskPlacement(ctx, c, "vm1", "vda", "h", "/new", "dir", "p2"); !errors.Is(err, ErrNoRowsAffected) {
		t.Fatalf("placement on a tombstoned disk: err=%v, want ErrNoRowsAffected", err)
	}
	if after := mutationLogCount(t, c); after != before {
		t.Errorf("a refused placement on a tombstoned disk queued %d statement(s) for replication", after-before)
	}
}

// The strict path costs a real write nothing: one that changed a row is relayed.
func TestUpdateDiskPlacement_AChangeStillReplicates(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	if err := InsertVM(ctx, c, VMRecord{Name: "vm1", HostName: "h", Spec: "{}", State: "stopped"}, nil,
		[]DiskRecord{{VMName: "vm1", DiskName: "vda", HostName: "h", Path: "/old", StorageType: "dir", StorageVolume: "p1"}}); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	before := mutationLogCount(t, c)
	if err := UpdateDiskPlacement(ctx, c, "vm1", "vda", "h", "/new", "dir", "p2"); err != nil {
		t.Fatalf("UpdateDiskPlacement: %v", err)
	}
	if after := mutationLogCount(t, c); after <= before {
		t.Fatal("a placement that changed a row was not relayed; the move would exist on this node only")
	}
}

// The other behaviour class. ExecuteRows callers that only COUNT — a retention
// sweep, a bulk lease hand-off — keep today's semantics: a zero-row UPDATE is
// relayed, and a full-PK one whose row is absent is parked, exactly as Execute
// does (TestExecute_ANonCreateNoOpIsUnaffected pins the Execute half).
func TestExecuteRows_ANonStrictZeroRowIsStillRelayedAndParked(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	before := mutationLogCount(t, c)
	n, err := c.ExecuteRows(ctx, `UPDATE hosts SET state = ?, updated_at = ? WHERE name = ?`,
		"active", c.NowTS(), "no-such-host")
	if err != nil || n != 0 {
		t.Fatalf("ExecuteRows: n=%d err=%v", n, err)
	}
	if after := mutationLogCount(t, c); after <= before {
		t.Error("a non-strict zero-row UPDATE was suppressed; the row it targets may be one this node lacks")
	}
	if got := c.ParkedUpdates(); got != 1 {
		t.Errorf("parked = %d, want 1: a non-strict full-PK update whose row is absent waits for it", got)
	}
}

// ExecuteRowsStrict directly: the zero-row case sends and parks nothing, the
// changed case relays.
func TestExecuteRowsStrict_RelaysOnlyAChange(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	seedHost(t, c, "h1")
	before := mutationLogCount(t, c)
	n, err := c.ExecuteRowsStrict(ctx, `UPDATE hosts SET state = ?, updated_at = ? WHERE name = ?`,
		"active", c.NowTS(), "no-such-host")
	if err != nil || n != 0 {
		t.Fatalf("ExecuteRowsStrict (absent): n=%d err=%v", n, err)
	}
	if after := mutationLogCount(t, c); after != before {
		t.Errorf("a zero-row strict UPDATE queued %d statement(s)", after-before)
	}
	if got := c.ParkedUpdates(); got != 0 {
		t.Errorf("a zero-row strict UPDATE parked %d update(s)", got)
	}
	n, err = c.ExecuteRowsStrict(ctx, `UPDATE hosts SET state = ?, updated_at = ? WHERE name = ?`,
		"draining", c.NowTS(), "h1")
	if err != nil || n != 1 {
		t.Fatalf("ExecuteRowsStrict (present): n=%d err=%v", n, err)
	}
	if after := mutationLogCount(t, c); after <= before {
		t.Error("a strict UPDATE that changed a row was not relayed")
	}
}

func wantErr(got, want error) error {
	if !errors.Is(got, want) {
		return errors.Join(errors.New("unexpected result"), got)
	}
	return nil
}

func wantFalse(ok bool, err error) error {
	if err != nil {
		return err
	}
	if ok {
		return errors.New("reported applied on an empty database")
	}
	return nil
}
