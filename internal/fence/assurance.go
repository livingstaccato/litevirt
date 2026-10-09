package fence

// The one classification of a fence (colonelpanik/litevirt#253).
//
// A fence has two descriptions that used to be judged apart: the Result a
// strategy returns, and the fencing_log (method, result) row it is recorded as.
// The coordinator decided "the host is proved off" from the first and the
// shared-storage gate from the second, by different rules, so an SSH success
// was proof of power-off for the host state and for resuming a recovery while
// it was not proof for a shared disk. Every judgement now goes through
// Assurance, here, in a package both sides already depend on: corrosion's
// FenceAssurance and FenceProofGrade delegate to it, and the coordinator asks
// Result.ProvedOff.

// fencing_log.result values a fence writes.
const (
	// LogFenced: the strategy reported success. What that ESTABLISHES depends
	// on the method (Assurance); the column alone cannot say.
	LogFenced = "fenced"
	// LogPartial: the strategy reported failure, or a manual fence is waiting
	// for an operator.
	LogPartial = "partial"
	// LogManualConfirmed: an operator ran `lv host fence-confirm`.
	LogManualConfirmed = "manual-confirmed"
)

// Assurance levels: what a recorded fence actually establishes about the
// host, as opposed to what its result string says happened.
const (
	// AssuranceVerified: the host was powered off AND observed off afterwards
	// (IPMI: chassis power off, then a power-status read that says off).
	AssuranceVerified = "verified"
	// AssuranceOperatorConfirmed: a human ran `lv host fence-confirm` after
	// ensuring the host is down.
	AssuranceOperatorConfirmed = "operator-confirmed"
	// AssuranceRequested: the host accepted a poweroff (SSH) or the heartbeat
	// was stopped (watchdog), and nothing looked afterwards. The host may be
	// off; the record cannot say.
	AssuranceRequested = "requested"
	// AssuranceAssumed: the request itself is not known to have arrived. Only
	// the lenient best-effort path produces it — SSH failed and it proceeded.
	AssuranceAssumed = "assumed"
	// AssuranceSelfPaused: an assumed fence whose recovery waited out the
	// host's own partition pause. It says the old copy stopped EXECUTING, not
	// that the host is off. Assurance never returns it: it needs the row's
	// detail (corrosion.FenceAssuranceDetail).
	AssuranceSelfPaused = "self_paused"
	// AssuranceAwaitingConfirmation: a manual fence, waiting for a human.
	AssuranceAwaitingConfirmation = "awaiting-confirmation"
	// AssuranceFailed: the fence ran and reported failure.
	AssuranceFailed = "failed"
	// AssuranceUnknown: a pair this code does not recognise. Never a success.
	AssuranceUnknown = "unknown"
)

// Assurance classifies a fencing_log (method, result) pair. It is derived at
// read time from what every row already records, so it needs no schema change
// and classifies every historical row too.
func Assurance(method, result string) string {
	switch {
	case result == LogManualConfirmed:
		return AssuranceOperatorConfirmed
	case method == "manual" && result == LogPartial:
		return AssuranceAwaitingConfirmation
	case result == LogPartial:
		switch method {
		case "ipmi", "ssh", "watchdog", "best-effort-ssh":
			return AssuranceFailed
		}
	case result == LogFenced:
		switch method {
		case "ipmi":
			return AssuranceVerified
		case "ssh", "watchdog":
			return AssuranceRequested
		case "best-effort-ssh":
			return AssuranceAssumed
		}
	}
	return AssuranceUnknown
}

// ProofGrade reports whether a fencing_log (method, result) pair PROVES the
// host is powered off: a verified power-off, or an operator's confirmation.
// Nothing else — an SSH or watchdog request, a lenient best-effort, a failed
// or awaiting fence — proves it, however it is reported.
func ProofGrade(method, result string) bool {
	switch Assurance(method, result) {
	case AssuranceVerified, AssuranceOperatorConfirmed:
		return true
	default:
		return false
	}
}

// LogResult is the fencing_log result r is recorded with.
func (r Result) LogResult() string {
	if r.Success {
		return LogFenced
	}
	return LogPartial
}

// ProvedOff reports whether r proves the host is powered off, by the same
// rule as the row it is recorded as: ProofGrade(r.Method, r.LogResult()).
func (r Result) ProvedOff() bool {
	return ProofGrade(r.Method, r.LogResult())
}
