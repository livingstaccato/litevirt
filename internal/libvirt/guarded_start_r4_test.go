package libvirt

import (
	"errors"
	"strings"
	"testing"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// TestGuardedStart_FailedResumeStopsTheDomain (re-review m5): a domain
// started paused for its guard that then fails to resume is destroyed, as a
// guard refusal is: the start returns an error, and a paused domain left
// behind would disagree with the row it reports.
func TestGuardedStart_FailedResumeStopsTheDomain(t *testing.T) {
	destroyed := false
	err := guardedStart(StartGuard{Before: func(string) (bool, error) { return true, nil }}, "web",
		func(bool) error { return nil },
		func() error { return errors.New("resume failed") },
		func() { destroyed = true },
		func() bool { return !destroyed })
	if err == nil || !strings.Contains(err.Error(), "resume failed") {
		t.Fatalf("guardedStart = %v, want the resume failure", err)
	}
	if !destroyed {
		t.Error("a domain that could not be resumed was left paused")
	}
}

// Review I4: a paused start's end (PausedDone, which drops its start-paused
// record) is reported only once the start has really ended: the guest
// resumed, or the domain no longer paused. A create that failed but left a
// domain paused, or a destroy that did not land, keeps the record, so the
// sweep finds and names the paused guest.
//
// Mutation: report PausedDone unconditionally (the old defer) — red.
func TestGuardedStart_PausedDoneOnlyOnceTheStartEnded(t *testing.T) {
	boom := errors.New("connection reset by peer")
	for name, tc := range map[string]struct {
		create, after, resume error
		destroyLands          bool
		want                  bool // PausedDone reported
	}{
		"resumed":                               {want: true},
		"create failed, no domain left":         {create: boom, want: true},
		"create failed, the domain left paused": {create: boom, destroyLands: false, want: false},
		"guard refused, destroy landed":         {after: boom, destroyLands: true, want: true},
		"guard refused, destroy did not land":   {after: boom, want: false},
		"resume failed, destroy landed":         {resume: boom, destroyLands: true, want: true},
		"resume failed, destroy did not land":   {resume: boom, want: false},
	} {
		t.Run(name, func(t *testing.T) {
			created, paused, done, kept := false, false, false, false
			// "create failed, no domain left" creates nothing.
			leaveDomain := tc.create == nil || name == "create failed, the domain left paused"
			g := StartGuard{
				Before:      func(string) (bool, error) { return true, nil },
				AfterPaused: func(string) error { return tc.after },
				PausedDone:  func(string) { done = true },
				PausedKept:  func(string, error) { kept = true },
			}
			_ = guardedStart(g, "web",
				func(p bool) error {
					created, paused = leaveDomain, leaveDomain && p
					return tc.create
				},
				func() error {
					if tc.resume == nil {
						paused = false
					}
					return tc.resume
				},
				func() {
					if tc.destroyLands {
						created, paused = false, false
					}
				},
				func() bool { return created && paused })
			if done != tc.want {
				t.Fatalf("PausedDone reported = %v, want %v", done, tc.want)
			}
			if wantKept := !tc.want; kept != wantKept {
				t.Fatalf("PausedKept reported = %v, want %v", kept, wantKept)
			}
		})
	}
}

type stillPausedAPI struct {
	lookupErr, stateErr error
	state               golibvirt.DomainState
}

func (a stillPausedAPI) DomainLookupByName(name string) (golibvirt.Domain, error) {
	return golibvirt.Domain{Name: name}, a.lookupErr
}

func (a stillPausedAPI) DomainGetState(golibvirt.Domain, uint32) (int32, int32, error) {
	return int32(a.state), 0, a.stateErr
}

// domainStillPaused: only libvirt's no-such-domain, or a state other than
// paused, ends a paused start; anything it cannot read keeps the record.
//
// Mutation: an unreadable state counts as not paused — red.
func TestDomainStillPaused(t *testing.T) {
	noDomain := golibvirt.Error{Code: uint32(golibvirt.ErrNoDomain), Message: "Domain not found"}
	for name, tc := range map[string]struct {
		api  stillPausedAPI
		want bool
	}{
		"paused":              {api: stillPausedAPI{state: golibvirt.DomainPaused}, want: true},
		"shut off":            {api: stillPausedAPI{state: golibvirt.DomainShutoff}, want: false},
		"running":             {api: stillPausedAPI{state: golibvirt.DomainRunning}, want: false},
		"no such domain":      {api: stillPausedAPI{lookupErr: noDomain}, want: false},
		"lookup fails":        {api: stillPausedAPI{lookupErr: errors.New("connection reset")}, want: true},
		"state unreadable":    {api: stillPausedAPI{stateErr: errors.New("connection reset")}, want: true},
		"gone under the read": {api: stillPausedAPI{stateErr: noDomain}, want: false},
	} {
		if got := domainStillPaused(tc.api, "web"); got != tc.want {
			t.Errorf("%s: domainStillPaused = %v, want %v", name, got, tc.want)
		}
	}
}

// restoreAPI is the slice of snapshotAPI restoreWithRetry uses, over one
// domain whose state it tracks.
type restoreAPI struct {
	snapshotAPI
	state                 golibvirt.DomainState
	resumeErr, destroyErr error
}

func (a *restoreAPI) DomainRestoreFlags(string, golibvirt.OptString, uint32) error {
	a.state = golibvirt.DomainPaused
	return nil
}

func (a *restoreAPI) DomainLookupByName(name string) (golibvirt.Domain, error) {
	return golibvirt.Domain{Name: name}, nil
}

func (a *restoreAPI) DomainGetState(golibvirt.Domain, uint32) (int32, int32, error) {
	return int32(a.state), 0, nil
}

func (a *restoreAPI) DomainResume(golibvirt.Domain) error {
	if a.resumeErr != nil {
		return a.resumeErr
	}
	a.state = golibvirt.DomainRunning
	return nil
}

func (a *restoreAPI) DomainDestroy(golibvirt.Domain) error {
	if a.destroyErr != nil {
		return a.destroyErr
	}
	a.state = golibvirt.DomainShutoff
	return nil
}

// Review I4 and F7 m3 (X1): a restore the guard paused reports its end
// (PausedDone, which drops the start record) only once the domain resumed
// or is no longer paused; one left paused is reported kept (PausedKept),
// its record kept.
//
// Mutation: restoreWithRetry's PausedDone unconditional — red.
func TestRestoreWithRetry_PausedDoneOnlyOnceTheStartEnded(t *testing.T) {
	boom := errors.New("boom")
	for name, tc := range map[string]struct {
		api        restoreAPI
		after      error
		done, kept bool
	}{
		"resumed":                             {done: true},
		"resume failed, left paused":          {api: restoreAPI{resumeErr: boom}, kept: true},
		"guard refused, destroy landed":       {after: boom, done: true},
		"guard refused, destroy did not land": {api: restoreAPI{destroyErr: boom}, after: boom, kept: true},
	} {
		t.Run(name, func(t *testing.T) {
			done, kept := false, false
			g := StartGuard{
				Before:      func(string) (bool, error) { return true, nil },
				AfterPaused: func(string) error { return tc.after },
				PausedDone:  func(string) { done = true },
				PausedKept:  func(string, error) { kept = true },
			}
			api := tc.api
			_ = restoreWithRetry(&api, g, FirmwareMoveGuard{}, "web", "/saved", "")
			if done != tc.done || kept != tc.kept {
				t.Fatalf("PausedDone %v, PausedKept %v; want %v, %v", done, kept, tc.done, tc.kept)
			}
		})
	}
}
