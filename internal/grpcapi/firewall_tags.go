package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Firewall tags (firewall extras spec §4.3): `lv firewall tag set|rm|ls`.
//
// A workload's tags are one row keyed by its firewall identity (fw_id). Every
// tag set or rm mints the identity first (corrosion.MintFirewallID), on the
// workload's OWNER: the mint keeps the identity the row holds unless another
// live row holds the same one (a copy), and then mints a fresh one and
// abandons the copied id, whose tags row is cleared here so the copy, now its
// only holder, inherits nothing. The write needs sg.write at the cluster root
// (fwTagAuthority) and waits for the firewall_tag_groups release latch.

// fwTagKind maps the request's kind onto the store's.
func fwTagKind(kind string) (string, error) {
	switch kind {
	case "vm":
		return corrosion.TagMemberVM, nil
	case "container", "ct":
		return corrosion.TagMemberCT, nil
	}
	return "", status.Errorf(codes.InvalidArgument, "kind %q: want vm or container", kind)
}

// pbFWTagKind is the API's spelling of a store kind.
func pbFWTagKind(kind string) string {
	if kind == corrosion.TagMemberCT {
		return "container"
	}
	return "vm"
}

// fwTagsText is a tag set as the audit and the notes show it: sorted k=v
// pairs in braces, or none.
func fwTagsText(tags map[string]string) string {
	if len(tags) == 0 {
		return corrosion.AuditStateNone
	}
	var pairs []string
	for _, k := range slices.Sorted(maps.Keys(tags)) {
		pairs = append(pairs, k+"="+tags[k])
	}
	return "{" + strings.Join(pairs, " ") + "}"
}

// fwTagTarget is the audit target of a workload's tags.
func fwTagTarget(kind, host, name string) string {
	if kind == corrosion.TagMemberCT {
		return host + "/" + name
	}
	return name
}

// fwTagMintError maps a refused mint onto a status.
func fwTagMintError(err error) error {
	switch {
	case errors.Is(err, corrosion.ErrFirewallIDNotMinted):
		return status.Errorf(codes.Aborted, "%v", err)
	case errors.Is(err, corrosion.ErrFirewallIDNoCreateSpec):
		return status.Errorf(codes.FailedPrecondition,
			"%v: recreate the container (lv ct rm, then lv ct create) before tagging it", err)
	case errors.Is(err, corrosion.ErrFirewallIDMoveOpen), errors.Is(err, corrosion.ErrClusterPolicyGateClosed):
		return status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	if _, ok := status.FromError(err); ok {
		return err
	}
	return status.Errorf(codes.Internal, "%v", err)
}

// SetFirewallTags sets, then removes, firewall tags of one workload. Needs
// sg.write at the cluster root; refused until the firewall_tag_groups
// release latch; audited as firewall.tag.set (any key set) or
// firewall.tag.rm, with the tags before and after. Runs on the workload's
// owner, which mints its identity.
func (s *Server) SetFirewallTags(ctx context.Context, req *pb.SetFirewallTagsRequest) (*pb.FirewallTags, error) {
	auth, err := s.fwTagAuthority(ctx)
	if err != nil {
		return nil, err
	}
	kind, err := fwTagKind(req.GetKind())
	if err != nil {
		return nil, err
	}
	name := req.GetWorkload()
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "workload required")
	}
	if len(req.GetSet()) == 0 && len(req.GetRemove()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "nothing to set or remove")
	}
	for k, v := range req.GetSet() {
		if !corrosion.ValidFirewallTagWord(k) || !corrosion.ValidFirewallTagWord(v) {
			return nil, status.Errorf(codes.InvalidArgument,
				"tag %s=%s: a key and a value are each [a-z0-9][a-z0-9_.-]{0,62}", k, v)
		}
	}
	for _, k := range req.GetRemove() {
		if !corrosion.ValidFirewallTagWord(k) {
			return nil, status.Errorf(codes.InvalidArgument, "tag key %q: want [a-z0-9][a-z0-9_.-]{0,62}", k)
		}
	}
	if err := s.ReleaseFeatureRefusal(ctx, capabilities.FeatureFirewallTagGroups); err != nil {
		return nil, err
	}

	// The owner: a VM's host, or the container's.
	host, owner := "", ""
	switch kind {
	case corrosion.TagMemberVM:
		vm, err := corrosion.GetVM(ctx, s.db, name)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "look up VM %q: %v", name, err)
		}
		if vm == nil {
			return nil, status.Errorf(codes.NotFound, "VM %q not found", name)
		}
		owner = vm.HostName
	default:
		h, _, err := s.resolveContainerHost(ctx, req.GetHost(), name)
		if err != nil {
			return nil, err
		}
		host, owner = h, h
	}
	actor := s.repairActor(ctx)
	if owner != s.hostName {
		if s.requirePeerCert(ctx) == nil && hasRepairActor(ctx) {
			// Forwarded here as the owner, but this replica names another.
			return nil, status.Errorf(codes.Aborted, "%s %q is owned by %s on this host's replica; retry", pbFWTagKind(kind), name, owner)
		}
		c, closePeer, err := s.dialPeer(ctx, owner)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "reach host %s, which owns %s %q: %v", owner, pbFWTagKind(kind), name, err)
		}
		defer closePeer()
		fwd := &pb.SetFirewallTagsRequest{Kind: req.GetKind(), Workload: name, Host: host, Set: req.GetSet(), Remove: req.GetRemove()}
		return c.SetFirewallTags(metadata.AppendToOutgoingContext(ctx, repairActorMDKey, actor), fwd)
	}

	action := "firewall.tag.rm"
	if len(req.GetSet()) > 0 {
		action = "firewall.tag.set"
	}
	var id, abandoned, before string
	var after map[string]string
	err = s.WithReleaseFeature(ctx, capabilities.FeatureFirewallTagGroups, func(ctx context.Context, g capabilities.FeatureGrant) error {
		var err error
		id, abandoned, err = corrosion.MintFirewallID(ctx, s.db, g, kind, host, name)
		if err != nil {
			return fwTagMintError(err)
		}
		if abandoned != "" {
			// The copied id stays with the other holder: its tags must not.
			if err := corrosion.ClearFirewallTags(ctx, s.db, g, kind, abandoned); err != nil {
				return status.Errorf(codes.Internal,
					"%s %q held a copied firewall identity %s, now replaced by %s; clearing the copied identity's tags failed, "+
						"so the other holder keeps them until the orphan sweep: %v", pbFWTagKind(kind), name, abandoned, id, err)
			}
		}
		cur, _, err := corrosion.ResolveFirewallTags(ctx, s.db, kind, id)
		if err != nil {
			return status.Errorf(codes.Internal, "read the tags of %s %q: %v", pbFWTagKind(kind), name, err)
		}
		before = fwTagsText(cur.Tags)
		if cur.Unreadable {
			// Rewritten from what this request sets: the row grants nothing as
			// it stands (spec §4.6).
			before = "unreadable"
		}
		after = maps.Clone(cur.Tags)
		if after == nil {
			after = map[string]string{}
		}
		maps.Copy(after, req.GetSet())
		for _, k := range req.GetRemove() {
			delete(after, k)
		}
		if err := corrosion.SetFirewallTags(ctx, s.db, g, auth, kind, id, after, name, host, actor); err != nil {
			if errors.Is(err, corrosion.ErrClusterPolicyGateClosed) {
				return status.Errorf(codes.FailedPrecondition, "%v", err)
			}
			return status.Errorf(codes.Internal, "write the tags of %s %q: %v", pbFWTagKind(kind), name, err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	detail := "fw_id=" + id
	if abandoned != "" {
		detail += " replaced_copied_fw_id=" + abandoned
	}
	s.auditAs(ctx, actor, action, fwTagTarget(kind, host, name), detail+" "+corrosion.AuditChange(before, fwTagsText(after)), "ok")
	s.reconcileLocal(ctx)
	out := &pb.FirewallTags{Kind: pbFWTagKind(kind), Workload: name, Host: host, FwId: id, Tags: after, SetBy: actor}
	if rec, ok, err := corrosion.ResolveFirewallTags(ctx, s.db, kind, id); err == nil && ok {
		out.UpdatedAt = rec.UpdatedAt
	}
	return out, nil
}

// hasRepairActor reports whether ctx carries a forwarding entry node's actor.
func hasRepairActor(ctx context.Context) bool {
	md, ok := metadata.FromIncomingContext(ctx)
	return ok && len(md.Get(repairActorMDKey)) > 0
}

// fwTagWorkload is one live workload a list reports.
type fwTagWorkload struct {
	kind, host, name, fwID string
}

// ListFirewallTags lists firewall tags as this host's replica holds them.
// Needs sg.read at the cluster root. With no workload named: every live
// workload with tags. With one named: each live workload of that name (its
// identity and tags, none included), then each tags row whose display name is
// that name and whose identity no live workload holds (orphan: an earlier
// incarnation's, not applied).
func (s *Server) ListFirewallTags(ctx context.Context, req *pb.ListFirewallTagsRequest) (*pb.ListFirewallTagsResponse, error) {
	if err := s.RequirePerm(ctx, "/", sgReadVerb, "viewer"); err != nil {
		return nil, err
	}
	kinds := []string{corrosion.TagMemberVM, corrosion.TagMemberCT}
	if req.GetKind() != "" {
		k, err := fwTagKind(req.GetKind())
		if err != nil {
			return nil, err
		}
		kinds = []string{k}
	}
	var live []fwTagWorkload
	held := map[string]bool{}
	for _, kind := range kinds {
		if kind == corrosion.TagMemberVM {
			vms, err := corrosion.ListVMs(ctx, s.db, "", "")
			if err != nil {
				return nil, status.Errorf(codes.Internal, "list VMs: %v", err)
			}
			for _, vm := range vms {
				w := fwTagWorkload{kind: kind, name: vm.Name, fwID: corrosion.FirewallIDOf(kind, vm.Spec)}
				live, held[kind+"/"+w.fwID] = append(live, w), true
			}
			continue
		}
		cts, err := corrosion.ListContainers(ctx, s.db, "")
		if err != nil {
			return nil, status.Errorf(codes.Internal, "list containers: %v", err)
		}
		for _, ct := range cts {
			w := fwTagWorkload{kind: kind, host: ct.HostName, name: ct.Name, fwID: corrosion.FirewallIDOf(kind, ct.CreateSpec)}
			live, held[kind+"/"+w.fwID] = append(live, w), true
		}
	}
	rows, err := corrosion.ListFirewallTagsRows(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list firewall tags: %v", err)
	}
	byID := map[string]corrosion.FirewallTagsRecord{}
	for _, r := range rows {
		byID[r.Kind+"/"+r.FWID] = r
	}
	named := req.GetWorkload() != ""
	out := &pb.ListFirewallTagsResponse{}
	for _, w := range live {
		if named && (w.name != req.GetWorkload() || (req.GetHost() != "" && w.host != req.GetHost())) {
			continue
		}
		e := &pb.FirewallTags{Kind: pbFWTagKind(w.kind), Workload: w.name, Host: w.host, FwId: w.fwID}
		if w.fwID != "" {
			if r, ok := byID[w.kind+"/"+w.fwID]; ok {
				e.Tags, e.SetBy, e.UpdatedAt = r.Tags, r.SetBy, r.UpdatedAt
			}
		}
		if !named && len(e.Tags) == 0 {
			continue
		}
		out.Tags = append(out.Tags, e)
	}
	if named {
		if len(out.Tags) == 0 {
			return nil, status.Errorf(codes.NotFound, "no workload named %q", req.GetWorkload())
		}
		for _, r := range rows {
			if !slices.Contains(kinds, r.Kind) || held[r.Kind+"/"+r.FWID] || r.Name != req.GetWorkload() || len(r.Tags) == 0 {
				continue
			}
			out.Tags = append(out.Tags, &pb.FirewallTags{Kind: pbFWTagKind(r.Kind), Workload: r.Name, Host: r.Host,
				FwId: r.FWID, Tags: r.Tags, SetBy: r.SetBy, UpdatedAt: r.UpdatedAt, Orphan: true})
		}
	}
	sort.SliceStable(out.Tags, func(i, j int) bool {
		a, b := out.Tags[i], out.Tags[j]
		if a.Orphan != b.Orphan {
			return !a.Orphan
		}
		if a.Kind != b.Kind {
			return a.Kind > b.Kind // VMs first
		}
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		return a.Workload < b.Workload
	})
	return out, nil
}

// ── Lifecycle ──

// fwTagClearGateTimeout bounds the release gate a delete's clear goes
// through: the delete has happened, and the gate may still ask peers.
const fwTagClearGateTimeout = 10 * time.Second

// clearDeletedFirewallTags clears the tags row of a workload a plain delete
// removed (spec §4.3): unconditionally once firewall_tag_groups is recorded
// used here — whatever this replica holds for the row, which may lag the
// write — and never before (no row can exist anywhere then, and a clear must
// not be a first use). A failure is logged; the delete stands, and the orphan
// sweep clears the row within its grace. Moves and re-creates never call it.
func (s *Server) clearDeletedFirewallTags(ctx context.Context, kind, name, fwID string) {
	if fwID == "" {
		return
	}
	info, _ := capabilities.LookupFeature(capabilities.FeatureFirewallTagGroups)
	if used, err := corrosion.ReleaseFeatureUsed(ctx, s.db, info.Token, string(capabilities.FeatureFirewallTagGroups)); err != nil || !used {
		if err != nil {
			slog.Warn("delete: could not read whether firewall tags are in use; the orphan sweep clears the deleted workload's tags",
				"kind", kind, "name", name, "fw_id", fwID, "error", err)
		}
		return
	}
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), fwTagClearGateTimeout)
	defer cancel()
	if err := s.WithReleaseFeature(wctx, capabilities.FeatureFirewallTagGroups, func(wctx context.Context, g capabilities.FeatureGrant) error {
		return s.clearFirewallTagsHook(wctx, g, kind, fwID)
	}); err != nil {
		slog.Warn("delete: the deleted workload's firewall tags were not cleared; the orphan sweep clears them",
			"kind", kind, "name", name, "fw_id", fwID, "error", err)
	}
}

// clearFirewallTagsHook is ClearFirewallTags, replaced by a test to make the
// clear fail.
func (s *Server) clearFirewallTagsHook(ctx context.Context, g capabilities.FeatureGrant, kind, fwID string) error {
	if s.testClearFirewallTags != nil {
		return s.testClearFirewallTags(ctx, kind, fwID)
	}
	return corrosion.ClearFirewallTags(ctx, s.db, g, kind, fwID)
}

// entryClearsFirewallTagsMD marks a delete an entry node forwarded to the
// owner: the entry clears the deleted workload's firewall tags, so the owner
// does not (a re-create's delete must not clear them at all, and only the
// entry knows it is one).
const entryClearsFirewallTagsMD = "x-litevirt-fw-tags-entry"

// forwardedByEntry reports whether a peer host (or local root) forwarded this
// delete and clears the tags itself.
func (s *Server) forwardedByEntry(ctx context.Context) bool {
	if s.requirePeerCert(ctx) != nil {
		return false
	}
	md, ok := metadata.FromIncomingContext(ctx)
	return ok && len(md.Get(entryClearsFirewallTagsMD)) > 0
}

// entryForwardCtx marks an outgoing delete forward (forwardedByEntry).
func entryForwardCtx(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(ctx, entryClearsFirewallTagsMD, "1")
}

// ── Notes about tags left behind ──

// firewallTagsLeftForID is the note naming the tags the incarnation with
// identity fwID left on its row, which do not follow what replaced it, and
// the command an sg.write holder runs to set them again on the workload now
// named name. lead says what happened, and is given the identity. "" when
// that row holds none.
func (s *Server) firewallTagsLeftForID(ctx context.Context, kind, fwID, name, host, lead string) string {
	if fwID == "" {
		return ""
	}
	rec, ok, err := corrosion.ResolveFirewallTags(ctx, s.db, kind, fwID)
	if err != nil {
		slog.Warn("could not read the firewall tags left behind", "kind", kind, "name", name, "fw_id", fwID, "error", err)
		return ""
	}
	if !ok || rec.Unreadable {
		return ""
	}
	return firewallTagsLeftText(kind, name, host, fmt.Sprintf(lead, fwID), rec.Tags)
}

// firewallTagsLeftText formats a note about tags left behind: lead, the
// tags, and the command that sets them again. "" when there are none.
func firewallTagsLeftText(kind, name, host, lead string, tags map[string]string) string {
	var pairs []string
	for _, k := range slices.Sorted(maps.Keys(tags)) {
		if corrosion.ValidFirewallTagWord(k) && corrosion.ValidFirewallTagWord(tags[k]) {
			pairs = append(pairs, k+"="+tags[k])
		}
	}
	if len(pairs) == 0 {
		return ""
	}
	cmd := "lv firewall tag set " + name
	if kind == corrosion.TagMemberCT {
		cmd += " --container --host " + host
	}
	return fmt.Sprintf("%s: %s. To set them again (sg.write): %s %s", lead, strings.Join(pairs, " "), cmd, strings.Join(pairs, " "))
}
