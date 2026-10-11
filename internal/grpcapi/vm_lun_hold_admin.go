package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Seeing and clearing the moved holds (re-review 4, m-1 and m-4).
//
// A hold is released only on evidence (vm_lun_hold.go), so one can stand for
// as long as its run host cannot be asked — and a record that does not parse
// stops this host answering any LUN question. Neither may be invisible, and
// neither may need a restart or a hand edit to clear:
//
//   - `lv host lun-holds [host]` lists a host's holds, and any record it
//     cannot read;
//   - `lv host lun-hold discard <lun>` (admin, audited) moves the records that
//     name a LUN, a token or a file aside, to iscsi-lun-holds/discarded/
//     (kept, never deleted), and reloads the holds at once;
//   - the resolver raises iscsi_lun_hold_unreadable (critical) while the
//     records cannot be read, naming the file, and iscsi_lun_hold_standing
//     (warning) for a hold older than lunHoldStandingAfter, naming the VM, its
//     LUNs and its run host. Each node writes these about itself only.

const (
	lunHoldEvaluator = "iscsi_lun_hold"
	// condLUNHoldUnreadable: this host's hold records cannot be read, so it
	// answers no LUN question (every iSCSI create here, and every walk that
	// must ask it, is refused).
	condLUNHoldUnreadable = "iscsi_lun_hold_unreadable"
	// condLUNHoldStanding: a hold has stood longer than lunHoldStandingAfter.
	condLUNHoldStanding = "iscsi_lun_hold_standing"
	// lunHoldStandingAfter is how old a hold is before it is reported.
	lunHoldStandingAfter = 5 * time.Minute
	// lunHoldDiscardedDir is where discarded records are kept.
	lunHoldDiscardedDir = "discarded"
)

// lunHoldHealth is what this process last wrote of each condition: the
// detail of the open row, "" when none is open. loaded once the rows an
// earlier process left were read.
type lunHoldHealth struct {
	loaded     bool
	unreadable string
	standing   string
}

// ISCSILUNHolds is `lv host lun-holds` and `lv host lun-hold discard`. The
// records are files on that host, so the request is answered there.
func (s *Server) ISCSILUNHolds(ctx context.Context, req *pb.ISCSILUNHoldsRequest) (*pb.ISCSILUNHoldsResponse, error) {
	role := "viewer"
	if req.Discard != "" {
		role = "admin" // it can let a create take a LUN a guest may still use
	}
	if err := RequireRole(ctx, role); err != nil {
		return nil, err
	}
	if req.Host != "" && req.Host != s.hostName {
		client, conn, err := s.peerClient(ctx, req.Host)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", req.Host, err)
		}
		defer conn.Close()
		return client.ISCSILUNHolds(ctx, req)
	}
	resp := &pb.ISCSILUNHoldsResponse{Host: s.hostName}
	if req.Discard != "" {
		moved, err := s.discardLUNHolds(req.Discard)
		result, detail := "ok", fmt.Sprintf("discarded iSCSI LUN hold records %s on %s (matching %q)",
			strings.Join(moved, ", "), s.hostName, req.Discard)
		if err != nil {
			result, detail = "error", fmt.Sprintf("discard iSCSI LUN holds matching %q on %s: %v", req.Discard, s.hostName, err)
		}
		if err == nil || len(moved) > 0 {
			s.audit(ctx, "host.lun_hold.discard", s.hostName, detail, result)
		}
		if err != nil {
			return nil, err
		}
		resp.Discarded = moved
		slog.Warn("iSCSI LUN: hold records discarded by an operator", "records", moved, "match", req.Discard)
	}
	holds, loadErr, err := s.listLUNHolds()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list the iSCSI LUN holds: %v", err)
	}
	resp.Holds = holds
	if loadErr != nil {
		resp.LoadError = loadErr.Error()
	}
	return resp, nil
}

// listLUNHolds is every record on disk, read afresh — those that do not
// parse too — and the error that stops this host answering, if any.
func (s *Server) listLUNHolds() ([]*pb.ISCSILUNHold, error, error) {
	h := &s.lunHolds
	h.mu.Lock()
	defer h.mu.Unlock()
	loadErr := s.lunHoldsLocked() // retries an I/O error
	if s.dataDir == "" {
		return nil, loadErr, nil
	}
	ents, err := lunHoldReadDir(s.lunHoldDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, loadErr, nil
	}
	if err != nil {
		return nil, loadErr, err
	}
	var out []*pb.ISCSILUNHold
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(s.lunHoldDir(), e.Name())
		rec, perr, ioErr := readLUNHoldFile(path)
		if perr == nil {
			perr = ioErr
		}
		if perr != nil {
			out = append(out, &pb.ISCSILUNHold{File: e.Name(), Error: perr.Error()})
			continue
		}
		out = append(out, &pb.ISCSILUNHold{File: e.Name(), Token: rec.Token, VmName: rec.VM, Luns: rec.LUNs,
			RunHost: rec.RunHost, Since: rec.Since, ReplacedCreatedAt: rec.ReplacedCreatedAt,
			NewCreatedAt: rec.NewCreatedAt, Active: h.active[rec.Token]})
	}
	return out, loadErr, nil
}

// lunHoldMatches reports whether match names the record in file (rec nil
// when it does not parse): its file name, its token, or a LUN it holds.
func lunHoldMatches(match, file string, rec *lunHoldRecord) bool {
	if match == file || match == strings.TrimSuffix(file, ".json") {
		return true
	}
	if rec == nil {
		return false
	}
	_, ok := rec.LUNs[match]
	return ok
}

// discardLUNHolds moves every record match names aside, to
// iscsi-lun-holds/discarded/, and reloads the holds. A hold whose re-create
// is still running here is refused: it is released when that re-create
// returns, on its evidence.
func (s *Server) discardLUNHolds(match string) ([]string, error) {
	h := &s.lunHolds
	h.mu.Lock()
	defer h.mu.Unlock()
	if s.dataDir == "" {
		return nil, status.Error(codes.NotFound, "this host keeps no iSCSI LUN holds")
	}
	dir := s.lunHoldDir()
	ents, err := lunHoldReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		ents, err = nil, nil
	}
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "read the iSCSI LUN holds in %s: %v", dir, err)
	}
	var names []string
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		rec, _, _ := readLUNHoldFile(filepath.Join(dir, e.Name()))
		if !lunHoldMatches(match, e.Name(), rec) {
			continue
		}
		if rec != nil && h.active[rec.Token] {
			return nil, status.Errorf(codes.FailedPrecondition,
				"the hold %s (VM %q) belongs to a re-create still running on %s; it is released when that "+
					"re-create returns and its evidence arrives", rec.Token, rec.VM, s.hostName)
		}
		names = append(names, e.Name())
	}
	if len(names) == 0 {
		return nil, status.Errorf(codes.NotFound, "no iSCSI LUN hold record on %s names %q", s.hostName, match)
	}
	aside := filepath.Join(dir, lunHoldDiscardedDir)
	if err := os.MkdirAll(aside, 0o700); err != nil {
		return nil, status.Errorf(codes.Internal, "make %s: %v", aside, err)
	}
	stamp := time.Now().UTC().Format("20060102T150405.000000000Z")
	var moved []string
	for _, n := range names {
		if err := os.Rename(filepath.Join(dir, n), filepath.Join(aside, n+"."+stamp)); err != nil {
			_ = s.reloadLUNHoldsLocked()
			return moved, status.Errorf(codes.Internal, "move %s aside: %v", n, err)
		}
		moved = append(moved, n)
	}
	for _, d := range []string{aside, dir} {
		if err := syncLUNHoldDir(d); err != nil {
			_ = s.reloadLUNHoldsLocked()
			return moved, status.Errorf(codes.Internal, "sync %s: %v", d, err)
		}
	}
	// The mirror is read again: a discarded record no longer holds anything,
	// and an unreadable one no longer stops the host answering.
	if err := s.reloadLUNHoldsLocked(); err != nil {
		slog.Warn("iSCSI LUN: the holds still cannot be read after a discard", "error", err)
	}
	return moved, nil
}

// lunHoldHealthPass brings this host's two conditions in line with its
// holds: iscsi_lun_hold_unreadable while they cannot be read, naming the
// file; iscsi_lun_hold_standing while a hold is older than
// lunHoldStandingAfter. It writes only on a change, and logs each change at
// WARN.
func (s *Server) lunHoldHealthPass(ctx context.Context, now time.Time) {
	h := &s.lunHolds
	h.mu.Lock()
	loadErr := s.lunHoldsLocked()
	bad := h.badFile
	var standing []string
	if loadErr == nil {
		for tok, rec := range h.recs {
			if h.active[tok] {
				continue
			}
			since, err := time.Parse(time.RFC3339Nano, rec.Since)
			if err != nil || now.Sub(since) < lunHoldStandingAfter {
				continue
			}
			standing = append(standing, fmt.Sprintf("VM %q holds %s on %s since %s for its re-create on %s, which "+
				"has not yet shown its rows here or that nothing there holds them (hold %s)",
				rec.VM, strings.Join(lunHoldKeys(rec), ", "), s.hostName, rec.Since, rec.RunHost, tok))
		}
	}
	h.mu.Unlock()
	sort.Strings(standing)

	if !h.health.loaded {
		for _, c := range []struct {
			code string
			dst  *string
		}{{condLUNHoldUnreadable, &h.health.unreadable}, {condLUNHoldStanding, &h.health.standing}} {
			row, ok, err := corrosion.GetHealthCondition(ctx, s.db, lunHoldEvaluator, c.code, "host", s.hostName)
			if err != nil {
				return // read again on the next pass
			}
			if ok && row.Lifecycle != corrosion.ConditionResolved {
				*c.dst = "(an earlier process's)"
			}
		}
		h.health.loaded = true
	}

	unreadable := ""
	if loadErr != nil {
		unreadable = fmt.Sprintf("the iSCSI LUN hold records on %s cannot be read (%v), so it answers no LUN "+
			"question: every iSCSI create on it, and every create elsewhere that must ask it, is refused. Check %s; "+
			"a record that does not parse is moved aside with `lv host lun-hold discard %s --host %s --yes` once "+
			"its VM is identified (docs/storage.md)", s.hostName, loadErr, bad, filepath.Base(bad), s.hostName)
	}
	s.setLUNHoldCondition(ctx, now, condLUNHoldUnreadable, corrosion.SeverityCritical, bad, unreadable, &h.health.unreadable)
	detail := ""
	if len(standing) > 0 {
		detail = strings.Join(standing, "; ") + ". Each is released only on evidence; list them with " +
			"`lv host lun-holds " + s.hostName + "` (docs/storage.md)"
	}
	s.setLUNHoldCondition(ctx, now, condLUNHoldStanding, corrosion.SeverityWarning, "", detail, &h.health.standing)
}

// setLUNHoldCondition opens (detail != "") or resolves (detail == "") one of
// this host's hold conditions, when that differs from *last.
func (s *Server) setLUNHoldCondition(ctx context.Context, now time.Time, code, severity, file, detail string, last *string) {
	if detail == *last {
		return
	}
	ts := now.UTC().Format(time.RFC3339)
	row := corrosion.HealthCondition{Evaluator: lunHoldEvaluator, Code: code, SubjectKind: "host",
		SubjectID: s.hostName, Hosts: []string{s.hostName}, Reporter: s.hostName, LastSeen: ts}
	if prev, ok, err := corrosion.GetHealthCondition(ctx, s.db, lunHoldEvaluator, code, "host", s.hostName); err == nil && ok {
		row.FirstSeen, row.ConfirmedAt, row.ObserveCount = prev.FirstSeen, prev.ConfirmedAt, prev.ObserveCount
	}
	if detail != "" {
		ev, _ := json.Marshal(struct {
			Detail string `json:"detail"`
			File   string `json:"file,omitempty"`
		}{detail, file})
		if row.FirstSeen == "" || *last == "" {
			row.FirstSeen, row.ConfirmedAt = ts, ts
		}
		row.Lifecycle, row.Severity, row.Evidence = corrosion.ConditionConfirmed, severity, string(ev)
		row.ObserveCount++
		slog.Warn("iSCSI LUN: "+code, "detail", detail)
	} else {
		row.Lifecycle, row.Severity, row.ResolvedAt, row.CleanCount = corrosion.ConditionResolved, severity, ts, 1
		slog.Warn("iSCSI LUN: "+code+" resolved", "host", s.hostName)
	}
	if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
		slog.Warn("iSCSI LUN: could not record a hold condition; retried on the next pass", "code", code, "error", err)
		return
	}
	*last = detail
}
