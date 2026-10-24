package fence

import (
	"context"
	"testing"
	"time"
)

func TestFenceManual_RequiresConfirmation(t *testing.T) {
	// Manual fence reports Success=false so the failover coordinator's
	// split-brain guard refuses to reschedule until an operator writes a
	// "manual-confirmed" row to fencing_log via `lv host fence-confirm`.
	// Old behavior (Success=true) silently bypassed the guard.
	h := HostConfig{
		Name:          "test-host",
		Address:       "10.0.0.5",
		FenceStrategy: "manual",
	}
	r := Execute(context.Background(), h)
	if r.Success {
		t.Errorf("manual fence must report Success=false until operator confirms; got success with detail: %s", r.Detail)
	}
	if r.Method != "manual" {
		t.Errorf("expected method=manual, got %q", r.Method)
	}
	if r.Detail == "" {
		t.Error("manual fence should return a Detail message instructing the operator")
	}
}

func TestFenceBestEffort_NoSSH_IsDialledNotFenced(t *testing.T) {
	// best-effort with an unreachable host (no SSH server) is a failure that
	// ran ssh: Dialled, which only the host's partition pause can make count.
	h := HostConfig{
		Name:          "unreachable",
		Address:       "192.0.2.1", // TEST-NET, unreachable
		SSHUser:       "root",
		SSHPort:       22,
		FenceStrategy: "best-effort",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r := Execute(ctx, h)
	if r.Success || !r.Dialled || r.WrongHost {
		t.Errorf("best-effort with SSH failing = %+v, want a dialled failure", r)
	}
	if r.Method != "best-effort-ssh" {
		t.Errorf("expected method=best-effort-ssh, got %q", r.Method)
	}
}

func TestFenceIPMI_MissingAddress_Fails(t *testing.T) {
	h := HostConfig{
		Name:          "no-ipmi",
		FenceStrategy: "ipmi",
		IPMIAddress:   "", // not configured
	}
	r := Execute(context.Background(), h)
	if r.Success {
		t.Error("IPMI fence without address should fail")
	}
	if r.Method != "ipmi" {
		t.Errorf("expected method=ipmi, got %q", r.Method)
	}
}

func TestFenceUnknownStrategy_FallsBackToBestEffort(t *testing.T) {
	h := HostConfig{
		Name:          "host1",
		Address:       "192.0.2.2",
		FenceStrategy: "nonexistent",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r := Execute(ctx, h)
	// Falls back to best-effort: best-effort-ssh, dialled, not a fence.
	if r.Method != "best-effort-ssh" {
		t.Errorf("expected fallback to best-effort-ssh, got %q", r.Method)
	}
	if r.Success || !r.Dialled {
		t.Errorf("fallback best-effort = %+v, want a dialled failure", r)
	}
}

func TestFenceEmpty_DefaultsBestEffort(t *testing.T) {
	h := HostConfig{
		Name:          "host1",
		Address:       "192.0.2.3",
		FenceStrategy: "", // empty = best-effort
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r := Execute(ctx, h)
	if r.Success || !r.Dialled || r.Method != "best-effort-ssh" {
		t.Errorf("empty strategy (best-effort) = %+v, want a dialled best-effort failure", r)
	}
}
