package grpcapi

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// auditGroupBindings records, for a login that verified directory groups,
// which groups the session carries and which role bindings each of them
// holds — so an operator can answer "why may this user do that" from the
// audit log, and see when a group grants nothing (a misspelt binding) or was
// not recorded at all (the login_policy release feature not open yet).
//
// What is audited is read back from the session as stored, not from the
// login's intent: it is what every node will evaluate.
func (s *Server) auditGroupBindings(ctx context.Context, subject, realm, token string, verified []string) {
	if realm == "local" || len(verified) == 0 {
		return
	}
	sid := strings.TrimPrefix(token, SessionTokenPrefix)
	recorded, err := corrosion.SessionGroups(ctx, s.db, sid, realm)
	if err != nil {
		s.audit(ctx, "auth.group_bindings", subject, "realm="+realm+" could not read back the session's groups: "+err.Error(), "error")
		return
	}
	if len(recorded) == 0 {
		s.audit(ctx, "auth.group_bindings", subject,
			fmt.Sprintf("realm=%s session=%s groups=%s not recorded: the login_policy release feature is not open on this "+
				"node, so group bindings do not apply to this session", realm, shortID(sid), strings.Join(verified, ",")), "skipped")
		return
	}
	var grants []string
	for _, g := range recorded {
		p := "group:" + g + "@" + realm
		for _, b := range s.authEngine.BindingsOf([]string{p}) {
			prop := ""
			if b.Propagate {
				prop = " (propagate)"
			}
			grants = append(grants, fmt.Sprintf("%s grants %s at %s%s [binding %s]", p, b.Role, b.Path, prop, b.ID))
		}
	}
	sort.Strings(grants)
	detail := fmt.Sprintf("realm=%s session=%s groups=%s", realm, shortID(sid), strings.Join(recorded, ","))
	if len(grants) == 0 {
		detail += "; no role binding names any of these groups"
	} else {
		detail += "; " + strings.Join(grants, "; ")
	}
	s.audit(ctx, "auth.group_bindings", subject, detail, "ok")
}
