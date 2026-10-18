package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// firmwareMoveFlags are the flags of `lv doctor firmware-move`.
type firmwareMoveFlags struct {
	acceptTarget, acceptSource, adopt, discard, confirmNvram, pushNvram, reverify bool
	resolve                                                                       string
	ack, stopTarget, jsonOut                                                      bool
	nvramHash                                                                     string
}

func newDoctorFirmwareMoveCmd() *cobra.Command {
	var f firmwareMoveFlags
	cmd := &cobra.Command{
		Use:   "firmware-move <vm>",
		Short: "Show or resolve a parked live firmware (Secure Boot / vTPM) migration",
		Long: `Show a VM's live firmware migration records on every host — the source's
marker, the target's hold, owed discards, quarantines and retained bundles —
with the VM's domain on each host and every hash and path. Read-only without
an action.

With one action it resolves a parked move, on the host whose record it acts on
(admin, vm.firmware-move; audited). Each action checks the move's state and
refuses where it has no row for it:

  --accept-target        take the target's verified copy: commit and release a
                         move verified there, resend Release after a V6 park,
                         finish the source cleanup of a released move, or
                         quarantine a source state that changed after cutover
  --reverify             hash the source's final state again and resend Verify
  --adopt-target-copy    take the target's copy without a Verify match (the
                         source's state is suspect or missing, the target ran,
                         or the source host is lost and fenced); or keep a
                         shut-off leftover as the VM's own once its row names
                         that host for the leftover's incarnation
  --accept-source        take the source's copy: discard the target's; after
                         the commit return the VM and its disks to the source
  --discard-target       discard the target's copy while the source's guest
                         runs, or a held copy no source marker names
  --confirm-target-nvram accept the target's NVRAM by its hash now
                         (--accept-nvram-hash)
  --push-source-nvram    write the source's final NVRAM to the target
  --resolve <code>       close firmware_migration_unverified or
                         firmware_migration_quarantine (nothing is touched)

--acknowledge-rollback is required where the source's copy may be older than
the target's. --stop-target stops a target guest that runs before its copy is
discarded or replaced.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req, err := f.request(args[0])
			if err != nil {
				return err
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.FirmwareMoveDoctor(ctx, req)
				if err != nil {
					return fmt.Errorf("firmware-move doctor: %w", err)
				}
				if f.jsonOut {
					enc := json.NewEncoder(os.Stdout)
					enc.SetIndent("", "  ")
					return enc.Encode(resp)
				}
				renderFirmwareMoveReport(os.Stdout, args[0], resp)
				return nil
			})
		},
	}
	fl := cmd.Flags()
	fl.BoolVar(&f.acceptTarget, "accept-target", false, "take the target's verified copy")
	fl.BoolVar(&f.acceptSource, "accept-source", false, "take the source's copy and discard the target's")
	fl.BoolVar(&f.adopt, "adopt-target-copy", false, "take the target's copy without a Verify match")
	fl.BoolVar(&f.discard, "discard-target", false, "discard the target's copy")
	fl.BoolVar(&f.confirmNvram, "confirm-target-nvram", false, "accept the target's NVRAM (with --accept-nvram-hash)")
	fl.BoolVar(&f.pushNvram, "push-source-nvram", false, "write the source's final NVRAM to the target")
	fl.BoolVar(&f.reverify, "reverify", false, "hash the source's final state again and resend Verify")
	fl.StringVar(&f.resolve, "resolve", "", "close a condition no move closes: unverified or quarantine")
	fl.BoolVar(&f.ack, "acknowledge-rollback", false, "accept that the source's copy may be older than the target's")
	fl.BoolVar(&f.stopTarget, "stop-target", false, "stop a target guest that runs first")
	fl.StringVar(&f.nvramHash, "accept-nvram-hash", "", "the target NVRAM's sha256 now, as shown")
	fl.BoolVar(&f.jsonOut, "json", false, "print the records as JSON")
	return cmd
}

// request is the RPC request the flags ask for: at most one action, and the
// modifiers only with an action that takes them.
func (f firmwareMoveFlags) request(vm string) (*pb.FirmwareMoveDoctorRequest, error) {
	req := &pb.FirmwareMoveDoctorRequest{VmName: vm, AcknowledgeRollback: f.ack, StopTarget: f.stopTarget,
		AcceptNvramHash: f.nvramHash, ResolveCondition: f.resolve}
	var picked []string
	for _, a := range []struct {
		on     bool
		flag   string
		action pb.FirmwareMoveDoctorAction
	}{
		{f.acceptTarget, "--accept-target", pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_ACCEPT_TARGET},
		{f.acceptSource, "--accept-source", pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_ACCEPT_SOURCE},
		{f.adopt, "--adopt-target-copy", pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_ADOPT_TARGET_COPY},
		{f.discard, "--discard-target", pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_DISCARD_TARGET},
		{f.confirmNvram, "--confirm-target-nvram", pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_CONFIRM_TARGET_NVRAM},
		{f.pushNvram, "--push-source-nvram", pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_PUSH_SOURCE_NVRAM},
		{f.reverify, "--reverify", pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_REVERIFY},
		{f.resolve != "", "--resolve", pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_RESOLVE_CONDITION},
	} {
		if a.on {
			picked = append(picked, a.flag)
			req.Action = a.action
		}
	}
	if len(picked) > 1 {
		return nil, fmt.Errorf("one action at a time: %s", strings.Join(picked, ", "))
	}
	a := req.Action
	if f.nvramHash != "" && a != pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_CONFIRM_TARGET_NVRAM {
		return nil, fmt.Errorf("--accept-nvram-hash goes with --confirm-target-nvram")
	}
	if a == pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_CONFIRM_TARGET_NVRAM && f.nvramHash == "" {
		return nil, fmt.Errorf("--confirm-target-nvram needs --accept-nvram-hash=<the target NVRAM's sha256 now>")
	}
	if f.ack && a != pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_ACCEPT_SOURCE &&
		a != pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_PUSH_SOURCE_NVRAM {
		return nil, fmt.Errorf("--acknowledge-rollback goes with --accept-source or --push-source-nvram")
	}
	if f.stopTarget && a != pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_ACCEPT_SOURCE &&
		a != pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_DISCARD_TARGET &&
		a != pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_PUSH_SOURCE_NVRAM {
		return nil, fmt.Errorf("--stop-target goes with --accept-source, --discard-target or --push-source-nvram")
	}
	return req, nil
}

// renderFirmwareMoveReport prints each host's records: both records, every
// hash and path.
func renderFirmwareMoveReport(w io.Writer, vm string, resp *pb.FirmwareMoveDoctorResponse) {
	if o := resp.GetOutcome(); o != "" {
		fmt.Fprintf(w, "%s\n\n", o)
	}
	found := false
	for _, h := range resp.GetHosts() {
		recs := h.GetMarkerJson() != "" || h.GetHoldJson() != "" || h.GetLeftoverJson() != "" || len(h.GetOwedDiscards()) > 0 ||
			len(h.GetQuarantines()) > 0 || len(h.GetRetained()) > 0 || h.GetError() != ""
		if !recs && !h.GetDomain().GetPresent() {
			continue
		}
		found = found || recs
		fmt.Fprintf(w, "host %s:\n", h.GetHost())
		if td := h.GetDomain(); td.GetPresent() {
			fmt.Fprintf(w, "  domain:       %s (reason %s, uuid %s)\n", td.GetState(), orDash(td.GetReason()), orDash(td.GetUuid()))
		}
		if j := h.GetMarkerJson(); j != "" {
			fmt.Fprintf(w, "  marker:       %s\n", recordLine(j, "phase", "parked_from", "target", "attempt", "route", "src_stop_reason",
				"src_permall_sha256", "src_nvram_sha256", "since", "detail"))
		}
		if j := h.GetHoldJson(); j != "" {
			fmt.Fprintf(w, "  hold:         %s\n", recordLine(j, "state", "source", "attempt", "nvram_materialised", "nvram_t0_sha256",
				"verified_permall_sha256", "since", "adoption"))
		}
		if j := h.GetLeftoverJson(); j != "" {
			fmt.Fprintf(w, "  leftover:     %s\n", recordLine(j, "source", "attempt", "uuid", "since"))
		}
		for _, o := range h.GetOwedDiscards() {
			fmt.Fprintf(w, "  owed discard: %s\n", recordLine(o, "target", "attempt", "since"))
		}
		for _, q := range h.GetQuarantines() {
			fmt.Fprintf(w, "  quarantine:   %s\n", q)
		}
		for _, r := range h.GetRetained() {
			fmt.Fprintf(w, "  retained:     %s\n", r)
		}
		for _, k := range sortedKeys(h.GetHashes()) {
			fmt.Fprintf(w, "  %-13s %s\n", k+":", h.GetHashes()[k])
		}
		for _, k := range sortedKeys(h.GetPaths()) {
			fmt.Fprintf(w, "  %-13s %s\n", k+":", h.GetPaths()[k])
		}
		if e := h.GetError(); e != "" {
			fmt.Fprintf(w, "  UNREADABLE:   %s\n", e)
		}
	}
	if !found {
		fmt.Fprintf(w, "no live firmware migration record names VM %s on any host that answered\n", vm)
	}
	for _, u := range resp.GetUnreachable() {
		fmt.Fprintf(w, "NOT READ: %s\n", u)
	}
}

// recordLine prints a record's fields, in order, as key=value.
func recordLine(j string, keys ...string) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(j), &m); err != nil {
		return j
	}
	var parts []string
	for _, k := range keys {
		v, ok := m[k]
		if !ok || v == nil || v == "" {
			continue
		}
		if sub, ok := v.(map[string]any); ok {
			b, _ := json.Marshal(sub)
			v = string(b)
		}
		parts = append(parts, fmt.Sprintf("%s=%v", k, v))
	}
	return strings.Join(parts, " ")
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
