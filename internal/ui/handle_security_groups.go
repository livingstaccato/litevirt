package ui

import (
	"net/http"
	"strconv"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// Security groups are read AND written through the daemon's security-group
// RPCs (internal/grpcapi/security_groups.go) with the session's bearer — the
// same handlers `lv sg` calls for its writes.
//
// That is what makes the two surfaces authorize one action identically
// (colonelpanik/litevirt#182). The pages used to check the generic "write" verb
// at "/" in-process, which only Admin's "*" grants, while the RPCs check
// "sg.write", which NetworkAdmin holds too — so a NetworkAdmin could manage
// security groups from the CLI and was refused in the browser. Worse, the
// in-process check resolved the caller from INCOMING gRPC metadata the UI never
// has, so on a cluster without strict mTLS identity it authorized every session
// as the bearerless admin. Routing through the RPCs leaves one check and one
// audit row, written by the handler that performed the change.
//
// The reads went the same way for the same reason. Read in-process, the page
// showed every group and rule to any session — a token scoped to one project,
// or a session whose Whoami had failed and been let through as a read.
// ListSecurityGroups checks sg.read at the cluster root, so the daemon refuses
// those on the read itself.

// sgRuleView is one rule as the page template prints it.
type sgRuleView struct {
	ID, Direction, Proto, PortRange, CIDR, Action string
}

// handleSecurityGroups renders /security-groups: every SG with its rules, plus
// create / add-rule / delete actions.
func (s *Server) handleSecurityGroups(w http.ResponseWriter, r *http.Request) {
	data := s.pageData("Security Groups", "security-groups")

	resp, err := s.grpc.ListSecurityGroups(s.uiBearerCtx(r), &pb.ListSecurityGroupsRequest{IncludeRules: true})
	if err != nil {
		s.renderPageRPCFailed(w, "security_groups.html", data, err)
		return
	}

	rulesBySG := map[string][]sgRuleView{}
	for _, rule := range resp.GetRules() {
		rulesBySG[rule.GetSgId()] = append(rulesBySG[rule.GetSgId()], sgRuleView{
			ID: rule.GetId(), Direction: rule.GetDirection(), Proto: rule.GetProto(),
			PortRange: rule.GetPort(), CIDR: rule.GetCidr(), Action: rule.GetAction(),
		})
	}
	type sgRow struct {
		ID, Name, Stack string
		Rules           []sgRuleView
	}
	rows := make([]sgRow, 0, len(resp.GetGroups()))
	for _, sg := range resp.GetGroups() {
		rows = append(rows, sgRow{
			ID: sg.GetId(), Name: sg.GetName(), Stack: sg.GetStackName(), Rules: rulesBySG[sg.GetId()],
		})
	}
	data["Groups"] = rows
	s.renderPage(w, "security_groups.html", data)
}

// handleSGCreateModal renders the "Create security group" modal.
func (s *Server) handleSGCreateModal(w http.ResponseWriter, r *http.Request) {
	s.renderFragment(w, "sg_create_modal.html", nil)
}

// handleCreateSG creates a security group. `lv sg create`, through the same RPC.
func (s *Server) handleCreateSG(w http.ResponseWriter, r *http.Request) {
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
	if _, err := s.grpc.CreateSecurityGroup(s.uiBearerCtx(r), &pb.CreateSecurityGroupRequest{
		Name: name, StackName: strings.TrimSpace(r.FormValue("stack")),
	}); err != nil {
		rpcWriteFailed(w, "Create", err)
		return
	}
	sendToast(w, "Security group "+name+" created", "success")
	w.Header().Set("HX-Redirect", "/security-groups")
	w.WriteHeader(http.StatusOK)
}

// handleDeleteSG removes a security group and its rules. `lv sg rm`, through
// the same RPC.
func (s *Server) handleDeleteSG(w http.ResponseWriter, r *http.Request) {
	if _, err := s.grpc.DeleteSecurityGroup(s.uiBearerCtx(r),
		&pb.DeleteSecurityGroupRequest{Id: r.PathValue("id")}); err != nil {
		rpcWriteFailed(w, "Delete", err)
		return
	}
	sendToast(w, "Security group deleted", "success")
	w.Header().Set("HX-Redirect", "/security-groups")
	w.WriteHeader(http.StatusOK)
}

// handleSGRuleModal renders the "Add rule" modal for one SG.
func (s *Server) handleSGRuleModal(w http.ResponseWriter, r *http.Request) {
	s.renderFragment(w, "sg_rule_modal.html", map[string]any{"SGID": r.PathValue("id")})
}

// handleAddSGRule appends a rule to a security group. `lv sg rule-add`, through
// the same RPC.
func (s *Server) handleAddSGRule(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	// Parsed at 32 bits, and any error (empty, junk, out of range) reads as 0,
	// the default, rather than wrapping into some other priority.
	priority, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("priority")), 10, 32)
	if err != nil {
		priority = 0
	}
	if _, err := s.grpc.AddSecurityGroupRule(s.uiBearerCtx(r), &pb.AddSecurityGroupRuleRequest{
		Rule: &pb.SecurityGroupRule{
			SgId:      r.PathValue("id"),
			Direction: r.FormValue("direction"),
			Proto:     r.FormValue("proto"),
			Port:      strings.TrimSpace(r.FormValue("port_range")),
			Cidr:      strings.TrimSpace(r.FormValue("cidr")),
			Action:    r.FormValue("action"),
			Priority:  int32(priority),
		},
	}); err != nil {
		rpcWriteFailed(w, "Add rule", err)
		return
	}
	sendToast(w, "Rule added", "success")
	w.Header().Set("HX-Redirect", "/security-groups")
	w.WriteHeader(http.StatusOK)
}

// handleDeleteSGRule removes a single rule. `lv sg rule-rm`, through the same
// RPC.
func (s *Server) handleDeleteSGRule(w http.ResponseWriter, r *http.Request) {
	if _, err := s.grpc.RemoveSecurityGroupRule(s.uiBearerCtx(r),
		&pb.RemoveSecurityGroupRuleRequest{Id: r.PathValue("rule")}); err != nil {
		rpcWriteFailed(w, "Delete rule", err)
		return
	}
	sendToast(w, "Rule removed", "success")
	w.Header().Set("HX-Redirect", "/security-groups")
	w.WriteHeader(http.StatusOK)
}
