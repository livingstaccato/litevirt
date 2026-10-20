package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// A fresh add refused over an earlier add's unsettled attempt printed the
// command that settles it only when the attempt's name was one the CLI takes
// in a command; for any other, "check it on the machine". `lv host rm
// --serial` takes every name that prints safely and is not read as a flag
// now, so the add prints the exact command for those, quoted as the removal
// quotes it, and that command, evaluated by sh, runs nothing else and
// settles the attempt. Only a name the removal would refuse keeps the
// dead end.
//
// Mutation: print the command only for validHostName names again — "a b"
// and the metacharacter names get the dead end.
func TestHostAdd_AnUnsettledAttemptsNamePrintsItsSettleCommand(t *testing.T) {
	for _, name := range []string{"a b", "x;touch${IFS}pwned", "$(touch pwned2)", "it's", "`touch pwned3`", "n|sh&&y"} {
		t.Run(name, func(t *testing.T) {
			f := newAddFixture(t)
			serial := strandedAddAs(t, f, name)
			installPair(t, f, "", "foreign")
			// A replica that does not list the attempt's joining row.
			f.client.hosts = []*pb.Host{{Name: "node-1", Address: "10.0.0.1", State: pb.HostState_HOST_ACTIVE, CertSerial: "a1"}}
			err := HostAddOn(context.Background(), f.client, f.target, "node-7", "10.0.0.9")
			want := settleCmd(hostAddPlan{hostName: name, hostAddr: "10.0.0.9"}, serial)
			if err == nil || !strings.Contains(err.Error(), "`"+want+"`") || strings.Contains(err.Error(), "check it on the machine") {
				t.Fatalf("fresh add = %v, want refused naming `%s`", err, want)
			}
			dir := t.TempDir()
			got := shellWords(t, dir, want)
			if strings.Join(got, "\x00") != strings.Join([]string{"lv", "host", "rm", name, "--serial", serial, "--address", "10.0.0.9"}, "\x00") {
				t.Fatalf("%q splits as %q", want, got)
			}
			if ents, _ := os.ReadDir(dir); len(ents) != 0 {
				t.Fatalf("evaluating %q ran something: %v", want, ents)
			}
			// The printed command, as sh split it, settles the attempt.
			m := &settleMachine{f: f, serial: serial, bBytes: mustRead(t, filepath.Join(f.targetPKI, "host.crt"))}
			m.dial(t, f.target)
			c := &serialRemoveClient{hostRemoveTestClient: &hostRemoveTestClient{}}
			if err := HostRemoveAdmission(context.Background(), c, got[3], got[5], got[7], false); err != nil {
				t.Fatalf("`%s`: %v", want, err)
			}
			if !serialInCRL(t, f.opPKI, serial) {
				t.Error("the attempt's serial was not revoked")
			}
			for _, p := range stagedOnTarget(t, f.target.Root) {
				if strings.Contains(filepath.Base(p), serial) {
					t.Errorf("left on the machine: %s", p)
				}
			}
			m.untouched(t)
		})
	}
	// A name the removal refuses (read as a flag) keeps the dead end: no
	// command is printed with it.
	t.Run("a name read as a flag", func(t *testing.T) {
		f := newAddFixture(t)
		serial := strandedAddAs(t, f, "node-9")
		recs, err := addRecords(f.target, serial)
		if err != nil || len(recs) == 0 {
			t.Fatalf("records %v, %v", recs, err)
		}
		for _, rec := range recs {
			if err := os.WriteFile(f.target.Path(addRecordPath(rec.tag)), []byte(addRecordLine("-rf", rec.before)), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		installPair(t, f, "", "foreign")
		f.client.hosts = []*pb.Host{{Name: "node-1", Address: "10.0.0.1", State: pb.HostState_HOST_ACTIVE, CertSerial: "a1"}}
		err = HostAddOn(context.Background(), f.client, f.target, "node-7", "10.0.0.9")
		if err == nil || !strings.Contains(err.Error(), "check it on the machine") || strings.Contains(err.Error(), "lv host rm") {
			t.Fatalf("fresh add = %v, want the dead end and no command", err)
		}
	})
}
