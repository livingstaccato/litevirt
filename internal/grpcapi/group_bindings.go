package grpcapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// maxGroupAuditDetail bounds one auth.group_bindings row (it is replicated
// and signed, once per login).
const maxGroupAuditDetail = 4096

// auditGroupBindings records, for a login that verified directory groups,
// which groups the session carries and which role bindings each of them
// holds — so an operator can answer "why may this user do that" from the
// audit log, and see when a group grants nothing (a misspelt binding) or was
// not recorded at all (the login_policy release feature not open yet).
//
// What is audited is read back from the session as stored, not from the
// login's intent: it is what every node will evaluate. The groups that hold a
// binding are named in full; the rest are a count and a hash of their names,
// and the whole detail is capped (maxGroupAuditDetail).
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
			capDetail(fmt.Sprintf("realm=%s session=%s %d verified groups not recorded: the login_policy release feature's gate "+
				"did not pass on this node (the feature is not open yet), so group bindings do not apply to this session",
				realm, shortID(sid), len(verified))), "skipped")
		return
	}
	var grants, rest []string
	for _, g := range recorded {
		p := auth.DirectoryGroupPrincipal(realm, g)
		bs := s.authEngine.BindingsOf([]string{p})
		if len(bs) == 0 {
			rest = append(rest, g)
			continue
		}
		for _, b := range bs {
			prop := ""
			if b.Propagate {
				prop = " (propagate)"
			}
			grants = append(grants, fmt.Sprintf("%s grants %s at %s%s [binding %s]", p, b.Role, b.Path, prop, b.ID))
		}
	}
	sort.Strings(grants)
	detail := fmt.Sprintf("realm=%s session=%s groups=%d", realm, shortID(sid), len(recorded))
	if len(grants) == 0 {
		detail += "; no role binding names any of these groups"
	} else {
		detail += "; " + strings.Join(grants, "; ")
	}
	if len(rest) > 0 {
		h := sha256.Sum256([]byte(strings.Join(rest, "\n")))
		detail += fmt.Sprintf("; %d groups hold no binding (sha256 of their sorted names %s)", len(rest), hex.EncodeToString(h[:8]))
	}
	s.audit(ctx, "auth.group_bindings", subject, capDetail(detail), "ok")
}

// capDetail cuts an audit detail at maxGroupAuditDetail bytes.
func capDetail(d string) string {
	if len(d) <= maxGroupAuditDetail {
		return d
	}
	const tail = " …(truncated)"
	return strings.ToValidUTF8(d[:maxGroupAuditDetail-len(tail)], "") + tail
}
