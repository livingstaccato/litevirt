package grpcapi

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// quarantinedLifecycleRefusal refuses a destructive lifecycle operation on a
// host in write quarantine, before it changes anything.
//
// Each of these operations removes something on the host (a domain, a disk,
// a root filesystem, a snapshot) and then records the removal on a
// replicated row, which the quarantine refuses. Going ahead would leave the
// cluster recording a workload or a snapshot whose data is gone: a rebuild
// left a `running` row on deleted disks, `lv ct rm` a live row with no
// container. None of them is needed to make a host safe (`lv stop --force`
// is), and none can be undone, so none is recorded locally to replay later.
//
// verb and what name the operation and its subject ("delete", `VM "web"`);
// lost says what would diverge; retry is the command to run again. A host
// that cannot record the operation also refuses it as the entry of a
// forward, because the entry records part of it (a delete's firewall tags
// and schedules): runElsewhere then adds that another host can take it.
func (s *Server) quarantinedLifecycleRefusal(verb, what, lost, retry string, runElsewhere bool) error {
	reason := s.stopQuarantineReason()
	if reason == "" {
		return nil
	}
	elsewhere := ""
	if runElsewhere {
		elsewhere = " (or run it from a host that is not in write quarantine)"
	}
	return status.Errorf(codes.FailedPrecondition,
		"cannot %s %s: host %s is in write quarantine (%s) and cannot record it, so %s; nothing was changed. "+
			"%s%s, then retry `%s`",
		verb, what, s.hostName, reason, lost, capitalize(s.quarantineRemedy()), elsewhere, retry)
}
