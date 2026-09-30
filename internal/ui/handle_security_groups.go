package ui

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/randid"
)

// Security-group CRUD is performed in-process against the host-local Corrosion
// handle (the same DB the read path uses), which CRDT-replicates the change
// cluster-wide; each host's firewall reconciler re-renders on its next tick.
// The `lv sg` CLI goes through the daemon's security-group RPCs instead
// (internal/grpcapi/security_groups.go), which record the same audit rows. These handlers run behind
// the UI's authenticated session but do NOT pass the gRPC RBAC interceptor —
// treat SG edits as an operator action (see docs/ui.md).

// handleSecurityGroups renders /security-groups: every SG with its rules, plus
// create / add-rule / delete actions.
func (s *Server) handleSecurityGroups(w http.ResponseWriter, r *http.Request) {
	data := s.pageData("Security Groups", "security-groups")

	if s.db == nil {
		data["Error"] = "corrosion DB not wired into UI server (build mismatch)"
		s.renderPage(w, "security_groups.html", data)
		return
	}

	sgs, err := corrosion.ListSecurityGroups(r.Context(), s.db, "")
	if err != nil {
		data["Error"] = err.Error()
		s.renderPage(w, "security_groups.html", data)
		return
	}

	type sgRow struct {
		ID, Name, Stack string
		Rules           []corrosion.SGRule
	}
	rows := make([]sgRow, 0, len(sgs))
	for _, sg := range sgs {
		rules, _ := corrosion.ListSGRules(r.Context(), s.db, sg.ID)
		rows = append(rows, sgRow{
			ID: sg.ID, Name: sg.Name, Stack: sg.StackName, Rules: rules,
		})
	}
	data["Groups"] = rows
	s.renderPage(w, "security_groups.html", data)
}

// handleSGCreateModal renders the "Create security group" modal.
func (s *Server) handleSGCreateModal(w http.ResponseWriter, r *http.Request) {
	s.renderFragment(w, "sg_create_modal.html", nil)
}

// handleCreateSG creates a security group. Mirrors `lv sg create`.
func (s *Server) handleCreateSG(w http.ResponseWriter, r *http.Request) {
	// This handler writes in-process rather than through the security-group
	// RPCs, so the daemon's authorizer is called directly. Without it this handler wrote
	// CRDT-replicated firewall state behind nothing but a coarse role string.
	if err := s.authorize(r, "/", "write"); err != nil {
		sendToast(w, "Not permitted: "+err.Error(), "error")
		w.WriteHeader(httpStatusFor(err))
		return
	}
	if s.db == nil {
		sendToast(w, "cluster DB unavailable", "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		sendToast(w, "Name is required", "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	id := randid.New()
	sg := corrosion.SecurityGroup{ID: id, Name: name, StackName: strings.TrimSpace(r.FormValue("stack"))}
	if err := corrosion.InsertSecurityGroup(r.Context(), s.db, sg); err != nil {
		sendToast(w, "Create failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.auditUIWrite(r, "sg.add", name, corrosion.AuditChange(corrosion.AuditStateNone, sg.AuditText(nil)))
	sendToast(w, "Security group "+name+" created", "success")
	w.Header().Set("HX-Redirect", "/security-groups")
	w.WriteHeader(http.StatusOK)
}

// handleDeleteSG removes a security group and its rules. Mirrors `lv sg rm`.
func (s *Server) handleDeleteSG(w http.ResponseWriter, r *http.Request) {
	// This handler writes in-process rather than through the security-group
	// RPCs, so the daemon's authorizer is called directly. Without it this handler wrote
	// CRDT-replicated firewall state behind nothing but a coarse role string.
	if err := s.authorize(r, "/", "write"); err != nil {
		sendToast(w, "Not permitted: "+err.Error(), "error")
		w.WriteHeader(httpStatusFor(err))
		return
	}
	if s.db == nil {
		sendToast(w, "cluster DB unavailable", "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	id := r.PathValue("id")
	// Read what is about to go, rules included: the group and its rules are
	// tombstoned together, and the audit row is then the only record of which
	// traffic they had been allowing or refusing (colonelpanik/litevirt#182).
	before := corrosion.SecurityGroupAuditState(r.Context(), s.db, id)
	_ = corrosion.DeleteSGRules(r.Context(), s.db, id)
	if err := corrosion.DeleteSecurityGroup(r.Context(), s.db, id); err != nil {
		sendToast(w, "Delete failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.auditUIWrite(r, "sg.rm", id, corrosion.AuditChange(before, corrosion.AuditStateNone))
	sendToast(w, "Security group deleted", "success")
	w.Header().Set("HX-Redirect", "/security-groups")
	w.WriteHeader(http.StatusOK)
}

// handleSGRuleModal renders the "Add rule" modal for one SG.
func (s *Server) handleSGRuleModal(w http.ResponseWriter, r *http.Request) {
	s.renderFragment(w, "sg_rule_modal.html", map[string]any{"SGID": r.PathValue("id")})
}

// handleAddSGRule appends a rule to a security group. Mirrors `lv sg rule-add`.
func (s *Server) handleAddSGRule(w http.ResponseWriter, r *http.Request) {
	// This handler writes in-process rather than through the security-group
	// RPCs, so the daemon's authorizer is called directly. Without it this handler wrote
	// CRDT-replicated firewall state behind nothing but a coarse role string.
	if err := s.authorize(r, "/", "write"); err != nil {
		sendToast(w, "Not permitted: "+err.Error(), "error")
		w.WriteHeader(httpStatusFor(err))
		return
	}
	if s.db == nil {
		sendToast(w, "cluster DB unavailable", "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	sgID := r.PathValue("id")
	id := randid.New()
	priority, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("priority")))
	if err := corrosion.InsertSGRule(r.Context(), s.db, corrosion.SGRule{
		ID:        id,
		SGID:      sgID,
		Direction: r.FormValue("direction"),
		Proto:     r.FormValue("proto"),
		PortRange: strings.TrimSpace(r.FormValue("port_range")),
		CIDR:      strings.TrimSpace(r.FormValue("cidr")),
		Action:    r.FormValue("action"),
		Priority:  priority,
	}); err != nil {
		sendToast(w, "Add rule failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// Read back, so the "after" is the rule as stored: the insert fills in the
	// defaults for an empty proto, action and priority.
	s.auditUIWrite(r, "sg.rule.add", sgID,
		corrosion.AuditChange(corrosion.AuditStateNone, corrosion.SGRuleAuditState(corrosion.GetSGRule(r.Context(), s.db, id))))
	sendToast(w, "Rule added", "success")
	w.Header().Set("HX-Redirect", "/security-groups")
	w.WriteHeader(http.StatusOK)
}

// handleDeleteSGRule removes a single rule.
func (s *Server) handleDeleteSGRule(w http.ResponseWriter, r *http.Request) {
	// This handler writes in-process rather than through the security-group
	// RPCs, so the daemon's authorizer is called directly. Without it this handler wrote
	// CRDT-replicated firewall state behind nothing but a coarse role string.
	if err := s.authorize(r, "/", "write"); err != nil {
		sendToast(w, "Not permitted: "+err.Error(), "error")
		w.WriteHeader(httpStatusFor(err))
		return
	}
	if s.db == nil {
		sendToast(w, "cluster DB unavailable", "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	ruleID := r.PathValue("rule")
	before := corrosion.SGRuleAuditState(corrosion.GetSGRule(r.Context(), s.db, ruleID))
	if err := corrosion.DeleteSGRule(r.Context(), s.db, ruleID); err != nil {
		sendToast(w, "Delete rule failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.auditUIWrite(r, "sg.rule.rm", ruleID, corrosion.AuditChange(before, corrosion.AuditStateNone))
	sendToast(w, "Rule removed", "success")
	w.Header().Set("HX-Redirect", "/security-groups")
	w.WriteHeader(http.StatusOK)
}
