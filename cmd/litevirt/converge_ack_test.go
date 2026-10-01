package main

import (
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func ackTD(name, hash string, ties, acked int32, residual string) *pb.TableDigest {
	return &pb.TableDigest{Name: name, Hash: hash, Count: 4, UnresolvedTies: ties,
		AcknowledgedTies: acked, AcknowledgedResidual: residual}
}

func convergenceLine(t *testing.T, out, table string) string {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, table+" ") {
			return l
		}
	}
	t.Fatalf("no %s row in:\n%s", table, out)
	return ""
}

// A table held apart only by ties every host has acknowledged, with every
// host's residual agreeing, is converged: it is listed as ACKNOWLEDGED so the
// evidence stays visible, and it counts toward the converged total.
func TestPrintConvergence_AcknowledgedTiesCountConverged(t *testing.T) {
	dig := &pb.ClusterStateDigestResponse{Hosts: []*pb.StateDigestResponse{
		host("a", ackTD("leader_lease_terms", "ha", 2, 2, "v2:same"), td("vms", "x", "", 1, 0)),
		host("b", ackTD("leader_lease_terms", "hb", 2, 2, "v2:same"), td("vms", "x", "", 1, 0)),
		host("c", ackTD("leader_lease_terms", "hc", 2, 2, "v2:same"), td("vms", "x", "", 1, 0)),
	}}
	out := captureStdout(t, func() { printConvergence(dig) })
	line := convergenceLine(t, out, "leader_lease_terms")
	if !strings.Contains(line, "ACKNOWLEDGED") || strings.Contains(line, "SAFETY-FAULT") {
		t.Errorf("want an ACKNOWLEDGED row, got %q", line)
	}
	if !strings.Contains(line, "6 acknowledged tie(s)") {
		t.Errorf("the row does not say how many acknowledged ties it holds: %q", line)
	}
	if !strings.Contains(out, "2/2 table(s) converged") {
		t.Errorf("a table held apart only by acknowledged ties was not counted converged:\n%s", out)
	}
}

// One unacknowledged tie anywhere keeps the table a SAFETY-FAULT, and it is not
// counted converged — a new claim must never read as reviewed.
func TestPrintConvergence_AnUnacknowledgedTieIsStillASafetyFault(t *testing.T) {
	dig := &pb.ClusterStateDigestResponse{Hosts: []*pb.StateDigestResponse{
		host("a", ackTD("leader_lease_terms", "ha", 2, 2, "v2:same")),
		host("b", ackTD("leader_lease_terms", "hb", 2, 1, "")),
	}}
	out := captureStdout(t, func() { printConvergence(dig) })
	line := convergenceLine(t, out, "leader_lease_terms")
	if !strings.Contains(line, "SAFETY-FAULT") {
		t.Errorf("an unacknowledged tie did not report SAFETY-FAULT: %q", line)
	}
	if !strings.Contains(line, "1 unacknowledged tie(s)") {
		t.Errorf("the row does not count the unacknowledged tie: %q", line)
	}
	if !strings.Contains(out, "0/1 table(s) converged") {
		t.Errorf("a table with an unacknowledged tie was counted converged:\n%s", out)
	}
}

// Every tie acknowledged, but the residuals disagree, or a host could not vouch
// for one: something else may differ beside the ties, so the table is not
// converged.
func TestPrintConvergence_AcknowledgedTiesDoNotHideOtherDrift(t *testing.T) {
	for name, hosts := range map[string][]*pb.StateDigestResponse{
		"residuals differ": {
			host("a", ackTD("leader_lease_terms", "ha", 1, 1, "v2:one")),
			host("b", ackTD("leader_lease_terms", "hb", 1, 1, "v2:two")),
		},
		"a host sent none": {
			host("a", ackTD("leader_lease_terms", "ha", 1, 1, "v2:one")),
			host("b", ackTD("leader_lease_terms", "hb", 1, 1, "")),
		},
		"a host tracks no tie": {
			host("a", ackTD("leader_lease_terms", "ha", 1, 1, "v2:one")),
			host("b", ackTD("leader_lease_terms", "hb", 0, 0, "")),
		},
	} {
		t.Run(name, func(t *testing.T) {
			out := captureStdout(t, func() {
				printConvergence(&pb.ClusterStateDigestResponse{Hosts: hosts})
			})
			line := convergenceLine(t, out, "leader_lease_terms")
			if strings.Contains(line, "ACKNOWLEDGED") && !strings.Contains(line, "SAFETY-FAULT") {
				t.Errorf("drift beside acknowledged ties read as ACKNOWLEDGED: %q", line)
			}
			if !strings.Contains(out, "0/1 table(s) converged") {
				t.Errorf("counted converged:\n%s", out)
			}
		})
	}
}
