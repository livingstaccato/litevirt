package grpcapi

import (
	"context"
	"fmt"
	"strings"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// gateRefusal is the operator-facing message of a split-brain gate refusal:
// "<what> refused: <reason>". When the reason is that this host is not an
// active worker because it is draining or in maintenance, it goes on to say
// so, and what to do: remedy, given this host's name and its state as a
// phrase ("is draining", "is in maintenance"). The bare reason,
// local_not_active_worker, names neither, so on its own an operator cannot
// tell a host taken out of service on purpose from a fault.
//
// Every other reason, and a host whose record cannot be read, keeps the bare
// message: the extra read happens only on a refusal, and never decides it.
func (s *Server) gateRefusal(ctx context.Context, what, reason string, remedy func(host, is string) string) string {
	msg := what + " refused: " + reason
	if reason != health.ReasonLocalNotActiveWorker {
		return msg
	}
	is, ok := s.localOutOfServiceState(ctx)
	if !ok {
		return msg
	}
	return fmt.Sprintf("%s — host %s %s, and takes on no new work until it is active again: %s",
		msg, s.hostName, is, remedy(s.hostName, is))
}

// localOutOfServiceState reports, as a phrase, whether this host's record
// says it was taken out of service by an operator: draining, or in
// maintenance. `lv host undrain` returns either to active.
func (s *Server) localOutOfServiceState(ctx context.Context) (string, bool) {
	h, err := corrosion.GetHost(ctx, s.db, s.hostName)
	if err != nil || h == nil {
		return "", false
	}
	switch h.State {
	case "draining":
		return "is draining", true
	case "maintenance":
		return "is in maintenance", true
	}
	return "", false
}

// startOnInactiveHostHint is how an operator starts a stopped VM on a host
// that is draining or in maintenance (is, as localOutOfServiceState phrases
// it): return the host to active first, or move the VM off — a move away is
// allowed there — and start it where it lands.
func startOnInactiveHostHint(vm, host, is string) string {
	return fmt.Sprintf("start it with `lv start %s` once %s is no longer %s (`lv host undrain %s`), "+
		"or move it off with `lv migrate %s <target-host> --cold` and start it there", vm, host, inactivePhrase(is), host, vm)
}

// restartRunningOnInactiveHostHint is startOnInactiveHostHint for a RUNNING
// VM's restart: a move off cold needs it stopped first, and a stop is allowed
// on a host out of service.
func restartRunningOnInactiveHostHint(vm, host, is string) string {
	return fmt.Sprintf("restart it with `lv restart %s` once %s is no longer %s (`lv host undrain %s`), "+
		"or stop it (`lv stop %s`), move it off with `lv migrate %s <target-host> --cold` and start it there",
		vm, host, inactivePhrase(is), host, vm, vm)
}

// returnToServiceHint is the remedy of a refusal with no VM-specific way
// around it: the host must be returned to active first.
func returnToServiceHint(host, _ string) string {
	return fmt.Sprintf("return it to active with `lv host undrain %s` first", host)
}

// inactivePhrase turns "is draining" / "is in maintenance" into the form that
// follows "no longer": "draining" / "in maintenance".
func inactivePhrase(is string) string {
	return strings.TrimPrefix(is, "is ")
}
