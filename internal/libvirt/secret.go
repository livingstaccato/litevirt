package libvirt

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"

	golibvirt "github.com/digitalocean/go-libvirt"
	"github.com/google/uuid"

	"github.com/litevirt/litevirt/internal/storage"
)

// Ceph secrets. A domain's rbd disk authenticates as a ceph client through a
// libvirt secret holding that client's key (<auth username=…><secret
// type='ceph' uuid=…/>); no domain element can name a keyring file. litevirt
// defines one secret per (litevirt pool, client id) on each host that has the
// pool, from the keyring the host's pool names.
//
// The UUID is DERIVED from the pool name and the client id rather than minted
// — and never from where a host keeps its keyring — so every host with the
// pool names the same secret: the domain XML a live migration hands the
// destination refers to a secret the destination holds, whatever its
// filesystem layout. Whether the destination's keyring holds the same KEY is
// checked separately (the pool rows' key fingerprints, grpcapi/ceph_secrets.go).
//
// The secrets are ephemeral (never written to /etc/libvirt) and private (the
// value cannot be read back through libvirt); the daemon re-defines them
// after a libvirtd restart.

// cephSecretNamespace is the UUIDv5 namespace litevirt's ceph secret UUIDs
// are derived in. Changing it renames every secret a running domain refers to.
var cephSecretNamespace = uuid.MustParse("6f1b3c0e-6a52-5d0c-9a49-1c2f3b6e8d10")

// CephSecretUsagePrefix starts the usage name of every ceph secret litevirt
// defines; nothing else is ever undefined by it.
const CephSecretUsagePrefix = "litevirt/ceph/"

// CephSecretUUID is the libvirt secret the disks of litevirt pool `pool`
// (a pool name, or "<stack>/<volume>") authenticating as client.<id> use.
func CephSecretUUID(pool, id string) string {
	return uuid.NewSHA1(cephSecretNamespace, []byte("pool\x00"+pool+"\x00"+id)).String()
}

// cephMonitorResolver returns a litevirt pool's current monitors on this host
// (its mon_host option, else its conf's); ok false when the host does not have
// the pool. Set once by the daemon (SetCephMonitorResolver).
var (
	cephMonitorMu       sync.RWMutex
	cephMonitorResolver func(pool string) ([]string, bool)
)

// SetCephMonitorResolver makes every rbd disk's domain take its monitors from
// the litevirt pool it names, as the pool is configured when the domain is
// defined. It returns the restore.
func SetCephMonitorResolver(f func(pool string) ([]string, bool)) (restore func()) {
	cephMonitorMu.Lock()
	prev := cephMonitorResolver
	cephMonitorResolver = f
	cephMonitorMu.Unlock()
	return func() {
		cephMonitorMu.Lock()
		cephMonitorResolver = prev
		cephMonitorMu.Unlock()
	}
}

// CephPoolMonitors returns a litevirt pool's current monitors on this host,
// the ones an rbd disk's domain defined now is given; ok is false when the
// host does not have the pool.
func CephPoolMonitors(pool string) ([]string, bool) { return poolMonitors(pool) }

func poolMonitors(pool string) ([]string, bool) {
	cephMonitorMu.RLock()
	f := cephMonitorResolver
	cephMonitorMu.RUnlock()
	if f == nil || pool == "" {
		return nil, false
	}
	return f(pool)
}

// cephSecretXML is the definition of a litevirt ceph secret. The value is set
// separately and never appears here.
func cephSecretXML(secretUUID, clientID string) string {
	return fmt.Sprintf(`<secret ephemeral='yes' private='yes'>
  <uuid>%s</uuid>
  <description>litevirt: ceph client.%s</description>
  <usage type='ceph'>
    <name>%s%s</name>
  </usage>
</secret>`, secretUUID, xmlEscape(clientID), CephSecretUsagePrefix, secretUUID)
}

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "'", "&apos;", `"`, "&quot;")
	return r.Replace(s)
}

func toLibvirtUUID(s string) (golibvirt.UUID, error) {
	u, err := uuid.Parse(s)
	if err != nil {
		return golibvirt.UUID{}, fmt.Errorf("secret uuid %q: %w", s, err)
	}
	return golibvirt.UUID(u), nil
}

// DefineCephSecret defines (or redefines) the ceph secret secretUUID for
// client.<clientID> and sets its value. Idempotent. The value is never logged
// nor part of an error.
func (c *Client) DefineCephSecret(secretUUID, clientID string, value []byte) error {
	if len(value) == 0 {
		return fmt.Errorf("ceph secret %s: empty value", secretUUID)
	}
	if _, err := toLibvirtUUID(secretUUID); err != nil {
		return err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	sec, err := c.virt.SecretDefineXML(cephSecretXML(secretUUID, clientID), 0)
	if err != nil {
		return fmt.Errorf("define ceph secret %s: %w", secretUUID, err)
	}
	if err := c.virt.SecretSetValue(sec, value, 0); err != nil {
		return fmt.Errorf("set ceph secret %s value: %w", secretUUID, err)
	}
	slog.Debug("ceph secret defined", "uuid", secretUUID, "client", clientID)
	return nil
}

// HasSecret reports whether libvirt holds the secret secretUUID.
func (c *Client) HasSecret(secretUUID string) (bool, error) {
	u, err := toLibvirtUUID(secretUUID)
	if err != nil {
		return false, err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if _, err := c.virt.SecretLookupByUUID(u); err != nil {
		if isNoSecret(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// ListCephSecrets returns the UUIDs of the ceph secrets litevirt defined
// (usage name under CephSecretUsagePrefix).
func (c *Client) ListCephSecrets() ([]string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	secs, _, err := c.virt.ConnectListAllSecrets(1, 0)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, s := range secs {
		if s.UsageType != int32(golibvirt.SecretUsageTypeCeph) || !strings.HasPrefix(s.UsageID, CephSecretUsagePrefix) {
			continue
		}
		out = append(out, uuid.UUID(s.UUID).String())
	}
	return out, nil
}

// UndefineSecret removes the secret secretUUID; one already gone is not an
// error.
func (c *Client) UndefineSecret(secretUUID string) error {
	u, err := toLibvirtUUID(secretUUID)
	if err != nil {
		return err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	sec, err := c.virt.SecretLookupByUUID(u)
	if err != nil {
		if isNoSecret(err) {
			return nil
		}
		return err
	}
	if err := c.virt.SecretUndefine(sec); err != nil && !isNoSecret(err) {
		return fmt.Errorf("undefine secret %s: %w", secretUUID, err)
	}
	return nil
}

func isNoSecret(err error) bool {
	if e, ok := err.(golibvirt.Error); ok && e.Code == uint32(golibvirt.ErrNoSecret) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "secret not found")
}

// CephSecretOfLocator returns the ceph secret an "rbd:" disk locator
// authenticates with, as its domain names it; ok is false for any other path
// and for a locator naming no keyring.
func CephSecretOfLocator(path string) (secretUUID string, ok bool) {
	l, isRBD := storage.ParseCephLocator(path)
	if !isRBD || l.Opts["keyring"] == "" || l.Opts["lvpool"] == "" {
		return "", false
	}
	return CephSecretUUID(l.Opts["lvpool"], cephID(l.Opts)), true
}

// cephID is the client a locator authenticates as: its id, or admin.
func cephID(opts map[string]string) string {
	if id := opts["id"]; id != "" {
		return id
	}
	return "admin"
}
