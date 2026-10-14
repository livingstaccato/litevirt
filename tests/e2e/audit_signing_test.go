package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Audit tamper-evidence against a live cluster.
//
// The fleet tests build their PKI in a temp directory and drive corrosion
// directly, so they prove the cryptography and the merge rules but say nothing
// about the two things that actually decide whether this works in production:
// whether the daemon can read the key material `lv host init` laid down on a
// real node, and whether the private key is protected on disk. A signing scheme
// whose key is world-readable is theatre — anyone who can read the file can
// forge the whole log — and no in-process test can see the file mode.
//
// These run on a cluster node (localMode) because they read the daemon's PKI
// directory and its database. From a workstation there is nothing to inspect,
// so they skip rather than pretend.

// auditPKIDir is where a node keeps its cluster identity, which is also its
// audit signing key. Matches pki_dir in the daemon config.
const auditPKIDir = "/etc/litevirt/pki"

func requireLocalNode(t *testing.T) {
	t.Helper()
	if !localMode {
		t.Skip("audit signing inspects the node's PKI dir and database; run on a cluster node")
	}
}

// thisHost is the name of the node the suite is running on.
//
// It does NOT read the package-level localHost, which TestSetup fills in: Go
// orders tests by filename, so this file runs BEFORE e2e_test.go and would see
// an empty string. That produced a confusing failure ("host \"\" has 0
// published signing certificates") that looked like a product bug and was
// purely test ordering.
func thisHost(t *testing.T) string {
	t.Helper()
	if localHost != "" {
		return localHost
	}
	data, err := os.ReadFile("/etc/litevirt/config.yaml")
	if err != nil {
		t.Skipf("cannot read the daemon config to learn this host's name: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "host_name:"); ok {
			return strings.Trim(strings.TrimSpace(rest), `"`)
		}
	}
	t.Skip("no host_name in the daemon config")
	return ""
}

// TestAuditSigningKeyIsNotReadableByOthers.
//
// The audit signature is only worth the secrecy of host.key. If any local user
// can read it they can sign rows as this host, and every peer will accept them
// — the certificate chains to the cluster CA and the CN matches, so nothing
// downstream has any reason to object. This is the one property of the whole
// design that lives in the filesystem rather than the code.
// It also covers every private key the node holds, not just the one that
// shipped loose: ca.key can mint an identity for any host in the cluster, and
// audit-signing.key is what a rotation installs precisely because the key it
// replaced was exposed. The repair runs at every daemon start regardless of
// enforcement.audit_signature — it used to hang off that flag, which then
// defaulted to false, so an operator who upgraded specifically for this fix and left the
// default got no repair at all. Only a live node can show that, because a file
// mode is invisible to a harness that mints its own PKI in a temp dir.
func TestAuditSigningKeyIsNotReadableByOthers(t *testing.T) {
	requireLocalNode(t)
	var checked int
	for _, name := range []string{"ca.key", "host.key", "audit-signing.key"} {
		keyPath := filepath.Join(auditPKIDir, name)
		fi, err := os.Stat(keyPath)
		if err != nil {
			continue // ca.key lives on one node; audit-signing.key only on rotated ones
		}
		checked++
		if mode := fi.Mode().Perm(); mode&0o077 != 0 {
			t.Errorf("%s is mode %04o; group/other can read it, so any local user can act as "+
				"this host — signing audit rows every peer accepts, and for host.key, "+
				"impersonating it over peer mTLS", keyPath, mode)
		}
	}
	if checked == 0 {
		t.Skipf("no private keys found under %s", auditPKIDir)
	}
}

// TestAuditVerifyReportsSigningState pins what `lv audit verify` tells an
// operator on a live cluster.
//
// The output has to be unambiguous in both directions: a clean log must not be
// reported in a way that can be mistaken for a finding, and unsigned rows must
// be visible without being called tampering. A cluster upgrading to v45 has a
// log full of unsigned rows, and if those read as an alarm operators learn to
// ignore the command entirely.
func TestAuditVerifyReportsSigningState(t *testing.T) {
	out, err := lvErr(t, "audit", "verify")
	if err != nil && strings.Contains(out, "AUDIT CHAIN FORKED") && !strings.Contains(out, "TAMPERED") {
		// A fork alone: the verifier found no edited, deleted or forged row, only
		// a second chain opened under a host name that already had one (the lab's
		// known artefact, which no test here made and no test here can heal). The
		// claim below, that a clean log reads as intact, cannot be made on it. The
		// run is excused only for the forks the operator named, as
		// E2E_KNOWN_AUDIT_FORK=<row-id>@<host>[,...]; see knownAuditFork. A fork
		// on another host, or any other shape, still fails.
		if ok, why := knownAuditFork(out, os.Getenv("E2E_KNOWN_AUDIT_FORK")); ok {
			t.Skipf("the log holds only the known forks %s, which this test did not create; verify says:\n%s", os.Getenv("E2E_KNOWN_AUDIT_FORK"), out)
		} else {
			t.Fatalf("the live cluster's audit chain is forked and it is not just the known fork (%s):\n%s", why, out)
		}
	}
	if err != nil {
		if !strings.Contains(out, "TAMPERED") {
			t.Fatalf("audit verify failed for a reason other than a finding: %v\n%s", err, out)
		}
		t.Fatalf("the live cluster's audit chain reports tampering:\n%s", out)
	}
	if !strings.Contains(out, "audit chain intact") {
		t.Fatalf("audit verify succeeded but did not say the chain is intact:\n%s", out)
	}
	if strings.Contains(out, "TAMPERED") {
		t.Fatalf("a clean verify printed the tampering headline:\n%s", out)
	}
	t.Logf("audit verify: %s", strings.TrimSpace(out))
}

// TestAuditRowsAreSignedWhenEnforcementIsOn.
//
// This is the end-to-end wiring check the fleet cannot make: config flag →
// daemon loads the key laid down by `lv host init` → a real audited action
// through the real CLI lands a row carrying a signature and a key id.
//
// It performs an action rather than reading old rows, because the log is full
// of rows written before signing was enabled and finding one of those proves
// nothing. Signing is on by default; if this node's config sets it false the
// test skips — that is a configuration choice, not a defect.
func TestAuditRowsAreSignedWhenEnforcementIsOn(t *testing.T) {
	requireLocalNode(t)
	if !auditSigningEnabled(t) {
		t.Skip("enforcement.audit_signature is off on this node")
	}

	project := "/e2e-audit-" + strconv.Itoa(os.Getpid())
	lv(t, "project", "create", project)
	t.Cleanup(func() { _, _ = lvErr(t, "project", "rm", project) })

	// The action must have produced a signed row attributed to this host.
	got := auditQuery(t, `SELECT count(*) FROM audit_log `+
		`WHERE target = '`+project+`' AND signature IS NOT NULL AND signature <> '' AND key_id <> ''`)
	if got != "1" {
		t.Fatalf("creating %s produced %q signed audit rows, want 1; the daemon is not signing "+
			"even though enforcement.audit_signature is on — check that it can read %s",
			project, got, filepath.Join(auditPKIDir, "host.key"))
	}

	// And this host's verification certificate must be published, or no peer
	// could ever check the row that was just written.
	host := thisHost(t)
	if n := auditQuery(t, `SELECT count(*) FROM audit_signing_keys WHERE host_name = '`+host+`'`); n != "1" {
		t.Fatalf("host %s has %q published signing certificates, want 1; its rows are signed but "+
			"unverifiable by every other node", host, n)
	}
}

// TestAuditChainHeadIsPublished.
//
// A head is the only thing that can detect a truncated tail — the hash chain
// links backward, so cutting the last rows leaves every surviving link
// verifying. The daemon publishes one at startup and every five minutes; a node
// that has written signed rows but published no head has lost that detection
// silently, which is exactly the failure this asserts against.
func TestAuditChainHeadIsPublished(t *testing.T) {
	requireLocalNode(t)
	if !auditSigningEnabled(t) {
		t.Skip("enforcement.audit_signature is off on this node")
	}
	host := thisHost(t)
	signed := auditQuery(t, `SELECT count(*) FROM audit_log WHERE host_name = '`+host+
		`' AND signature IS NOT NULL AND signature <> ''`)
	if signed == "0" {
		t.Skipf("host %s has written no signed rows yet; a head over an empty chain asserts nothing", host)
	}
	if n := auditQuery(t, `SELECT count(*) FROM audit_chain_heads WHERE host_name = '`+host+`'`); n == "0" {
		t.Fatalf("host %s has %s signed rows but has published no chain head; truncating its log "+
			"would leave every remaining link verifying and nothing would notice", host, signed)
	}
}

// auditSigningEnabled reports whether this node's config leaves signing on.
// Signing is the default, so only an explicit `audit_signature: false` turns it
// off — matching on `true` skipped these tests on every default-configured node,
// which is how a lab with signing never switched on went unnoticed.
func auditSigningEnabled(t *testing.T) bool {
	t.Helper()
	data, err := os.ReadFile("/etc/litevirt/config.yaml")
	if err != nil {
		t.Skipf("cannot read the daemon config: %v", err)
	}
	return !regexp.MustCompile(`(?m)^\s+audit_signature:\s*false\b`).Match(data)
}

// auditQuery reads a single scalar out of the node's state database.
//
// It goes to the database rather than the CLI on purpose: the point is to check
// what was actually STORED, and asking litevirt whether litevirt did the thing
// is exactly the shortcut this suite exists to avoid.
func auditQuery(t *testing.T, query string) string {
	t.Helper()
	sqlite, err := exec.LookPath("sqlite3")
	if err != nil {
		t.Skip("sqlite3 not available on this node; cannot inspect stored rows directly")
	}
	out, err := exec.Command(sqlite, "/var/lib/litevirt/state.db", query).Output()
	if err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	return strings.TrimSpace(string(out))
}

// knownAuditFork reports whether a fork-only `lv audit verify` output holds
// only the forks named by spec, a comma-separated list of "<row-id>@<host>",
// and nothing more:
//   - the row printed under the "forked chain" heading (the first broken link,
//     the only fork the verifier names by id) is one of the row ids, and
//   - the "sequence break" section holds only `<host>: row <id> repeats seq N`
//     lines, every one for one of the named hosts. A same-host fork may grow
//     more such lines as rows are appended, so the host is the granularity,
//     not the line set.
//
// A fork on a host the spec does not name, a first break that is not a named
// row, a deleted-rows gap, or no/malformed spec is not known.
func knownAuditFork(out, spec string) (bool, string) {
	ids, hosts := map[string]bool{}, map[string]bool{}
	for _, e := range strings.Split(spec, ",") {
		id, host, ok := strings.Cut(strings.TrimSpace(e), "@")
		if !ok || id == "" || host == "" {
			return false, "E2E_KNOWN_AUDIT_FORK is not set as <row-id>@<host>[,<row-id>@<host>...]"
		}
		ids[id], hosts[host] = true, true
	}
	lines := strings.Split(out, "\n")
	section := func(prefix string) (rows []string, found bool) {
		for i, l := range lines {
			if !strings.HasPrefix(l, prefix) {
				continue
			}
			for _, r := range lines[i+1:] {
				if strings.TrimSpace(r) == "" {
					break
				}
				rows = append(rows, strings.TrimSpace(r))
			}
			return rows, true
		}
		return nil, false
	}
	first, found := section("forked chain (")
	if !found || len(first) != 1 || !ids[first[0]] {
		return false, fmt.Sprintf("the first broken row is %v, not one of the known %s", first, spec)
	}
	gaps, found := section("sequence break (")
	if !found || len(gaps) == 0 {
		return false, "no sequence break section naming the fork's host"
	}
	for _, g := range gaps {
		h, rest, _ := strings.Cut(g, ": row ")
		if !hosts[h] || !strings.Contains(rest, " repeats seq ") {
			return false, fmt.Sprintf("a sequence-break line is not a duplicate on a known fork's host (%s): %q", spec, g)
		}
	}
	return true, ""
}

// TestKnownAuditFork pins what the E2E_KNOWN_AUDIT_FORK excuse covers.
// Run with LITEVIRT_E2E_UNIT=1 (it needs no cluster).
func TestKnownAuditFork(t *testing.T) {
	const head = "AUDIT CHAIN FORKED \u2014 100 rows checked (no edited, deleted or forged row found)\n\n"
	const first = "forked chain (the row hashes correctly but starts a second chain \u2014 empty prev_hash \u2014 for a host that already has one; see the duplicate seqs under sequence break):\n  b9fbdd30d8a95d0c\n"
	gap := func(host, id string) string {
		return "  " + host + ": row " + id + " repeats seq 7 (duplicate: two rows claim the same position, a forked chain)\n"
	}
	const spec = "b9fbdd30d8a95d0c@node-3"
	known := head + first + "\nsequence break (rows deleted from a host's chain, or a repeated seq \u2014 a forked chain):\n" +
		gap("node-3", "aaa") + gap("node-3", "bbb")
	if ok, why := knownAuditFork(known, spec); !ok {
		t.Errorf("the known fork alone was not excused: %s", why)
	}
	// Lab 1 (2026-10-14): a second fork on node-4 beside the named one, both
	// named.
	const both = spec + ",9bcb8393aec73858@node-4"
	if ok, why := knownAuditFork(known+gap("node-4", "9bcb8393aec73858"), both); !ok {
		t.Errorf("two named forks were not excused: %s", why)
	}
	if ok, why := knownAuditFork(known, both); !ok {
		t.Errorf("one of two named forks alone was not excused: %s", why)
	}
	for name, c := range map[string]struct{ out, spec string }{
		"a second fork on another host":  {known + gap("node-4", "ccc"), spec},
		"a third fork beside two named":  {known + gap("node-4", "ccc") + gap("node-5", "ddd"), both},
		"a list with a malformed entry":  {known, spec + ",node-4"},
		"the first break is another row": {strings.Replace(known, "b9fbdd30d8a95d0c", "ffffffffffffffff", 1), spec},
		"a deleted-rows gap":             {known + "  node-3: seq jumps from 4 to 9 (rows deleted)\n", spec},
		"no spec":                        {known, ""},
		"spec without a host":            {known, "b9fbdd30d8a95d0c"},
		"known id only as a later row":   {head + strings.Replace(first, "b9fbdd30d8a95d0c", "1111111111111111", 1) + "\nsequence break (x):\n" + gap("node-3", "b9fbdd30d8a95d0c"), spec},
	} {
		if ok, _ := knownAuditFork(c.out, c.spec); ok {
			t.Errorf("%s: was excused", name)
		}
	}
}
