package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/pki"
)

func newDoctorMigrationTLSCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "migration-tls",
		Short: "Show each host's storage-migration credentials and when they expire",
		Long: `Ask every host which migration CAs it trusts, which CA issued its migration
certificate, and when they expire. Read-only.

Exits non-zero when a host is unreachable, holds a set its daemon would refuse
to install, expires within 90 days, falls back to plaintext
(migration.allow_unencrypted_storage), or trusts a different CA set from its
peers while no 'lv host rotate-migration-ca' is running from this machine.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.MigrationTLSStatus(ctx, &pb.MigrationTLSStatusRequest{})
				if err != nil {
					return fmt.Errorf("migration TLS status: %w", err)
				}
				rows := resp.GetHosts()
				sort.Slice(rows, func(i, j int) bool { return rows[i].GetHost() < rows[j].GetHost() })
				now := time.Now()
				if asJSON {
					b, err := migrationTLSRowsJSON(rows)
					if err != nil {
						return err
					}
					os.Stdout.Write(b)
					os.Stdout.Write([]byte("\n"))
				} else {
					printMigrationTLSRows(rows, now)
				}
				problems := migrationTLSProblems(rows, cli.MigrationRotationInProgress(cli.PKIDir()), now)
				for _, p := range problems {
					fmt.Fprintln(os.Stderr, p)
				}
				if len(problems) > 0 {
					return fmt.Errorf("%d migration-TLS problem(s)", len(problems))
				}
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the rows as JSON")
	return cmd
}

// migrationTLSRowsJSON encodes rows as a JSON array, marshaling each row with
// protojson (UseProtoNames, so fields read e.g. cert_not_after) instead of
// plain encoding/json: a google.protobuf.Timestamp field encodes as an RFC
// 3339 string under protojson, where encoding/json would instead print its
// internal {"seconds":...,"nanos":...} representation — useless for a command
// whose whole point is showing operators when a credential expires.
func migrationTLSRowsJSON(rows []*pb.MigrationTLSHostStatus) ([]byte, error) {
	opts := protojson.MarshalOptions{UseProtoNames: true}
	raws := make([]json.RawMessage, len(rows))
	for i, r := range rows {
		b, err := opts.Marshal(r)
		if err != nil {
			return nil, fmt.Errorf("encode %s: %w", r.GetHost(), err)
		}
		raws[i] = b
	}
	return json.MarshalIndent(raws, "", "  ")
}

func shortFP(fp string) string {
	if len(fp) > 8 {
		return fp[:8] + "…"
	}
	return fp
}

func printMigrationTLSRows(rows []*pb.MigrationTLSHostStatus, now time.Time) {
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "HOST\tSTATUS\tTRUSTS\tCERT FROM\tEXPIRES")
	for _, r := range rows {
		state, trusts, from, expires := "ok", "—", "—", "—"
		switch {
		case r.GetError() != "":
			state, expires = "error", r.GetError()
		case !r.GetProvisioned():
			state = "none"
		case r.GetValidationError() != "", r.GetInstallError() != "":
			state = "invalid"
		}
		if len(r.GetTrustedCas()) > 0 {
			var fps []string
			for _, ca := range r.GetTrustedCas() {
				fps = append(fps, shortFP(ca.GetFingerprint()))
			}
			trusts = strings.Join(fps, ",")
		}
		if r.GetCertIssuerFingerprint() != "" {
			from = shortFP(r.GetCertIssuerFingerprint())
		}
		if t := r.GetCertNotAfter(); t != nil {
			left := int(t.AsTime().Sub(now).Hours() / 24)
			expires = fmt.Sprintf("%s (%dd)", t.AsTime().Format("2006-01-02"), left)
			if state == "ok" && t.AsTime().Before(now.Add(pki.MigrationExpiryWarning)) {
				state = "expiring"
			}
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", r.GetHost(), state, trusts, from, expires)
	}
	w.Flush()
}

// migrationTLSProblems lists, one line per finding, what makes the command exit
// non-zero. rotating is true while this machine has a rotation in progress,
// when hosts legitimately trust different CA sets.
func migrationTLSProblems(rows []*pb.MigrationTLSHostStatus, rotating bool, now time.Time) []string {
	var out []string
	sets := map[string][]string{}
	for _, r := range rows {
		h := r.GetHost()
		if r.GetError() != "" {
			out = append(out, fmt.Sprintf("%s: %s", h, r.GetError()))
			continue
		}
		if r.GetAllowUnencryptedStorage() {
			out = append(out, fmt.Sprintf("%s: falls back to plaintext storage migration "+
				"(migration.allow_unencrypted_storage is on)", h))
		}
		if !r.GetProvisioned() {
			out = append(out, fmt.Sprintf("%s: has no migration credentials; run `lv host install-migration-tls`", h))
			continue
		}
		if r.GetValidationError() != "" {
			out = append(out, fmt.Sprintf("%s: %s", h, r.GetValidationError()))
		}
		// The installer validates first, so its refusal of an invalid set
		// repeats the validation error; report it only when it says more.
		if ie := r.GetInstallError(); ie != "" &&
			(r.GetValidationError() == "" || !strings.Contains(ie, r.GetValidationError())) {
			out = append(out, fmt.Sprintf("%s: its daemon cannot install migration credentials: %s", h, ie))
		}
		deadline := now.Add(pki.MigrationExpiryWarning)
		if t := r.GetCertNotAfter(); t != nil && t.AsTime().Before(deadline) {
			out = append(out, fmt.Sprintf("%s: host certificate expires %s; run `lv host install-migration-tls --reissue`",
				h, t.AsTime().Format("2006-01-02")))
		}
		var fps []string
		for _, ca := range r.GetTrustedCas() {
			fps = append(fps, ca.GetFingerprint())
			if t := ca.GetNotAfter(); t != nil && t.AsTime().Before(deadline) {
				out = append(out, fmt.Sprintf("%s: CA %s expires %s; run `lv host rotate-migration-ca`",
					h, shortFP(ca.GetFingerprint()), t.AsTime().Format("2006-01-02")))
			}
		}
		sort.Strings(fps)
		key := strings.Join(fps, ",")
		sets[key] = append(sets[key], h)
	}
	if len(sets) > 1 && !rotating {
		var keys []string
		for k := range sets {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys[1:] {
			for _, h := range sets[k] {
				out = append(out, fmt.Sprintf("%s: trusts a different CA set from %s; if `lv host "+
					"rotate-migration-ca` is running from another machine, this is expected until it finishes",
					h, strings.Join(sets[keys[0]], ",")))
			}
		}
	}
	return out
}
