package pki

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/litevirt/litevirt/internal/safename"
)

// migrationPairSuffix is what the operator's PKI directory appends to a host
// name for that host's migration pair (<name>-migration.crt|.key).
const migrationPairSuffix = "-migration"

// MaxHostPathNameLen bounds a host name that becomes a file name: the longest
// one built from it, ".<name>-migration.crt.add", stays within a 255-byte
// file name.
const MaxHostPathNameLen = 230

// clientCertCN is the Common Name of the distributable client certificate.
const clientCertCN = "lv-cli"

// operatorPKIFiles are the files the operator's PKI directory holds of its
// own (lv host init/add mint them there). A host's pair is kept beside them
// as <name>.crt and <name>.key. host.*, ui.* and audit-signing.* are a node's
// files: the names are reserved for new hosts, but the operator's directory
// has none of its own under them.
var operatorPKIFiles = []string{
	"ca.crt", "ca.key", "client.crt", "client.key",
	GossipKeyName, MigrationCACertName, MigrationCAKeyName,
}

// reservedHostNames are the stems of fixedPKIFiles, and the client
// certificate's Common Name, which a host row of that name would make look
// like a peer.
var reservedHostNames = []string{
	"ca", "client", "host",
	strings.TrimSuffix(GossipKeyName, ".key"),
	strings.TrimSuffix(MigrationCACertName, ".crt"),
	strings.TrimSuffix(UICertName, ".crt"),
	strings.TrimSuffix(AuditSigningCertName, ".crt"),
	clientCertCN,
}

// ValidateHostPathName is the rule for any host name, new or admitted by an
// older build, that becomes part of a file name: not empty, not "." or "..",
// no '/', '\' or NUL, no leading '-', at most MaxHostPathNameLen bytes. It is
// what keeps a name from leaving the directory; older builds admitted any
// other name, so nothing more is asked of an existing host.
func ValidateHostPathName(name string) error {
	switch {
	case name == "":
		return errors.New("invalid host name: it is empty")
	case name == "." || name == "..":
		return fmt.Errorf("invalid host name %q: a path traversal", name)
	case strings.ContainsAny(name, "/\\\x00"):
		return fmt.Errorf("invalid host name %q: it contains a path separator or NUL", name)
	case strings.HasPrefix(name, "-"):
		return fmt.Errorf("invalid host name %q: it may not start with '-'", name)
	case len(name) > MaxHostPathNameLen:
		return fmt.Errorf("invalid host name %q: longer than %d bytes", name, MaxHostPathNameLen)
	}
	return nil
}

// ValidateExistingHostName is the rule for a name a host already holds where
// <name>.crt and <name>.key are written beside the cluster's files (resuming
// an add, re-admitting a removed name): ValidateHostPathName, and not one of
// the fixed files' stems or the client certificate's Common Name, compared
// case-insensitively because the operator's directory may be on a
// case-insensitive filesystem (macOS).
func ValidateExistingHostName(name string) error {
	if err := ValidateHostPathName(name); err != nil {
		return err
	}
	for _, r := range reservedHostNames {
		if strings.EqualFold(name, r) {
			return fmt.Errorf("invalid host name %q: reserved (%s)", name, strings.Join(reservedHostNames, ", "))
		}
	}
	return nil
}

// ValidateHostName is the rule for a NEW host name (`lv host init`, `lv host
// add`, AdmitHost of a name with no row): ValidateExistingHostName, safename's
// charset (letters, digits, '_', '.', '-'; at most safename.MaxNameLen), no
// leading '.', and no "-migration" suffix, which is another host's migration
// pair.
func ValidateHostName(name string) error {
	if err := ValidateExistingHostName(name); err != nil {
		return err
	}
	if err := safename.ValidateName(name); err != nil {
		return fmt.Errorf("invalid host name: %w", err)
	}
	if strings.HasPrefix(name, ".") {
		return fmt.Errorf("invalid host name %q: it may not start with '.'", name)
	}
	if len(name) > len(migrationPairSuffix) && strings.EqualFold(name[len(name)-len(migrationPairSuffix):], migrationPairSuffix) {
		return fmt.Errorf("invalid host name %q: a name ending in %q is another host's migration pair", name, migrationPairSuffix)
	}
	return nil
}

// OperatorPKIFileAt reports which of the operator directory's own files path
// is: the same name, or, on a case-insensitive filesystem, the same file
// under another case. It is the per-file check for a path built from a name
// an older build admitted.
func OperatorPKIFileAt(path string) (string, bool) {
	dir, base := filepath.Split(path)
	pi, perr := os.Stat(path)
	for _, f := range operatorPKIFiles {
		if base == f {
			return f, true
		}
		if perr != nil || !strings.EqualFold(base, f) {
			continue
		}
		if fi, err := os.Stat(filepath.Join(dir, f)); err == nil && os.SameFile(pi, fi) {
			return f, true
		}
	}
	return "", false
}

// OperatorPKIFileIn reports which of pkiDir's own files path is, wherever path
// is: OperatorPKIFileAt when path is directly in pkiDir, and otherwise (a
// kept copy under pkiDir/hosts/<name>/, say) the same file as one of them,
// through a hard or symbolic link.
func OperatorPKIFileIn(pkiDir, path string) (string, bool) {
	if filepath.Clean(filepath.Dir(path)) == filepath.Clean(pkiDir) {
		if f, ok := OperatorPKIFileAt(path); ok {
			return f, true
		}
	}
	pi, err := os.Stat(path)
	if err != nil {
		return "", false
	}
	for _, f := range operatorPKIFiles {
		if fi, err := os.Stat(filepath.Join(pkiDir, f)); err == nil && os.SameFile(pi, fi) {
			return f, true
		}
	}
	return "", false
}
