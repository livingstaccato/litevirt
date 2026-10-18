package contract

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"github.com/litevirt/litevirt/internal/safename"
	"math"
	"net"
	"reflect"
	"strings"
)

// CreateBindingBody carries only nonsecret requested input. Bootstrap input is
// represented by the private equality fields; effective bytes live in Ciphertext.
type CreateBindingBody struct {
	Version int      `json:"version"`
	Desired VMIntent `json:"desired"`
}
type ReferenceScope struct {
	ClusterUID string `json:"cluster_uid"`
	ProjectUID string `json:"project_uid,omitempty"`
	Global     bool   `json:"global,omitempty"`
}
type ScopedSelector struct {
	Scope ReferenceScope `json:"scope"`
	Name  string         `json:"name"`
}
type PinnedReference struct {
	Scope         ReferenceScope `json:"scope"`
	UID           string         `json:"uid"`
	Name          string         `json:"name"`
	ContentDigest string         `json:"content_digest,omitempty"`
}
type ReferenceInput struct {
	Selector *ScopedSelector  `json:"selector,omitempty"`
	Pinned   *PinnedReference `json:"pinned,omitempty"`
}
type ResourceReference struct {
	ClusterUID string `json:"cluster_uid"`
	ProjectUID string `json:"project_uid"`
	Kind       string `json:"kind"`
	UID        string `json:"uid"`
}
type HostReference struct {
	ClusterUID string `json:"cluster_uid"`
	UID        string `json:"uid"`
	Name       string `json:"name"`
}
type HostInput struct {
	Name   string         `json:"name,omitempty"`
	Pinned *HostReference `json:"pinned,omitempty"`
}
type PlacementIntent struct {
	Host            *HostInput          `json:"host,omitempty"`
	RequiredLabels  map[string]string   `json:"required_labels,omitempty"`
	PreferredLabels map[string]string   `json:"preferred_labels,omitempty"`
	Affinity        []ResourceReference `json:"affinity,omitempty"`
	AntiAffinity    []ResourceReference `json:"anti_affinity,omitempty"`
	MaxPerHost      uint32              `json:"max_per_host,omitempty"`
	Policy          string              `json:"policy,omitempty"`
}
type DiskIntent struct {
	Key       string          `json:"key"`
	SizeBytes uint64          `json:"size_bytes"`
	Pool      *ReferenceInput `json:"pool,omitempty"`
	Image     *ReferenceInput `json:"image,omitempty"`
	Bus       string          `json:"bus,omitempty"`
}
type NICIntent struct {
	Key         string         `json:"key"`
	Network     ReferenceInput `json:"network"`
	Model       string         `json:"model,omitempty"`
	MAC         *string        `json:"mac,omitempty"`
	IPv4CIDR    *string        `json:"ipv4_cidr,omitempty"`
	IPv4Gateway *string        `json:"ipv4_gateway,omitempty"`
	IPv6CIDR    *string        `json:"ipv6_cidr,omitempty"`
	IPv6Gateway *string        `json:"ipv6_gateway,omitempty"`
}
type VMIntent struct {
	Name                string            `json:"name"`
	CPU                 uint32            `json:"cpu"`
	MemoryMiB           uint64            `json:"memory_mib"`
	Labels              map[string]string `json:"labels,omitempty"`
	Placement           *PlacementIntent  `json:"placement,omitempty"`
	Image               *ReferenceInput   `json:"image,omitempty"`
	Disks               []DiskIntent      `json:"disks,omitempty"`
	NICs                []NICIntent       `json:"nics,omitempty"`
	RequestedState      string            `json:"requested_state,omitempty"`
	MaxCPU              *uint32           `json:"max_cpu,omitempty"`
	MemoryHotplugMaxMiB *uint64           `json:"memory_hotplug_max_mib,omitempty"`
}

// strictBindingObject checks exact nested spellings and required field presence
// before decoding. It is a schema decoder for the concrete structs above, not an
// arbitrary map accepted by the reducer. canonicalBody bounds bytes/depth and
// rejects duplicate fields before this walk.
func strictBindingObject(b []byte, out any) error {
	if _, err := canonicalBody(b); err != nil {
		return codedError(CodeValidation)
	}
	t := reflect.TypeOf(out)
	if t == nil || t.Kind() != reflect.Pointer || exactBindingJSON(b, t.Elem()) != nil {
		return codedError(CodeValidation)
	}
	if err := json.Unmarshal(b, out); err != nil {
		return codedError(CodeValidation)
	}
	return nil
}
func exactBindingJSON(b []byte, t reflect.Type) error {
	if bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
		return codedError(CodeValidation)
	}
	if t.Kind() == reflect.Pointer {
		return exactBindingJSON(b, t.Elem())
	}
	switch t.Kind() {
	case reflect.Struct:
		var raw map[string]json.RawMessage
		if json.Unmarshal(b, &raw) != nil || raw == nil {
			return codedError(CodeValidation)
		}
		allowed := make(map[string]bool, t.NumField())
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := strings.Split(f.Tag.Get("json"), ",")
			name := tag[0]
			allowed[name] = true
			value, present := raw[name]
			optional := len(tag) > 1 && tag[1] == "omitempty"
			if !present {
				if optional {
					continue
				}
				return codedError(CodeValidation)
			}
			if err := exactBindingJSON(value, f.Type); err != nil {
				return err
			}
		}
		for name := range raw {
			if !allowed[name] {
				return codedError(CodeValidation)
			}
		}
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			var value []byte
			if json.Unmarshal(b, &value) != nil {
				return codedError(CodeValidation)
			}
			canonical, _ := json.Marshal(value)
			if !bytes.Equal(bytes.TrimSpace(b), canonical) {
				return codedError(CodeValidation)
			}
			return nil
		}
		var values []json.RawMessage
		if json.Unmarshal(b, &values) != nil {
			return codedError(CodeValidation)
		}
		limit := 128
		if t.Elem() == reflect.TypeOf(RetainedPayload{}) || t.Elem() == reflect.TypeOf(PayloadCoverage{}) {
			limit = MaxRetainedPayloads
		}
		if len(values) > limit {
			return codedError(CodeValidation)
		}
		for _, value := range values {
			if err := exactBindingJSON(value, t.Elem()); err != nil {
				return err
			}
		}
	case reflect.Map:
		var values map[string]json.RawMessage
		if t.Key().Kind() != reflect.String || json.Unmarshal(b, &values) != nil || len(values) > 128 {
			return codedError(CodeValidation)
		}
		for key, value := range values {
			if len(key) > MaxStringBytes {
				return codedError(CodeValidation)
			}
			if err := exactBindingJSON(value, t.Elem()); err != nil {
				return err
			}
		}
	case reflect.String:
		var value string
		if json.Unmarshal(b, &value) != nil || len(value) > MaxStringBytes {
			return codedError(CodeValidation)
		}
	}
	return nil
}
func validReferenceScope(s ReferenceScope, cluster string) bool {
	return s.ClusterUID == cluster && s.Global != (s.ProjectUID != "")
}
func validContentDigest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && s == strings.ToLower(s)
}
func validPinned(r PinnedReference, cluster, kind string) bool {
	return validReferenceScope(r.Scope, cluster) && r.UID != "" && r.Name != "" && ((kind == "image" && validContentDigest(r.ContentDigest)) || (kind != "image" && r.ContentDigest == ""))
}
func validReferenceInput(r *ReferenceInput, cluster, kind string) bool {
	if r == nil {
		return true
	}
	if (r.Selector == nil) == (r.Pinned == nil) {
		return false
	}
	if r.Pinned != nil {
		return validPinned(*r.Pinned, cluster, kind)
	}
	return validReferenceScope(r.Selector.Scope, cluster) && r.Selector.Name != ""
}
func validResourceRef(r ResourceReference, cluster string) bool {
	return r.ClusterUID == cluster && r.ProjectUID != "" && r.Kind == "vm" && r.UID != ""
}
func validPlacement(p *PlacementIntent, cluster string) bool {
	if p == nil {
		return true
	}
	if p.Policy != "" && p.Policy != "balanced" && p.Policy != "pack" && p.Policy != "spread" {
		return false
	}
	if p.Host != nil {
		if (p.Host.Name == "") == (p.Host.Pinned == nil) {
			return false
		}
		if p.Host.Pinned != nil && (p.Host.Pinned.ClusterUID != cluster || p.Host.Pinned.UID == "" || p.Host.Pinned.Name == "") {
			return false
		}
	}
	seen := map[string]bool{}
	for _, set := range [][]ResourceReference{p.Affinity, p.AntiAffinity} {
		for _, r := range set {
			if !validResourceRef(r, cluster) || seen[r.UID] {
				return false
			}
			seen[r.UID] = true
		}
	}
	return true
}
func validNIC(n NICIntent, cluster string) bool {
	if n.Key == "" || !validReferenceInput(&n.Network, cluster, "network") || (n.Model != "" && n.Model != "virtio" && n.Model != "e1000") {
		return false
	}
	if n.MAC != nil {
		mac, err := net.ParseMAC(*n.MAC)
		if err != nil || len(mac) != 6 || mac[0]&1 != 0 {
			return false
		}
	}
	for _, entry := range []struct {
		cidr, gateway *string
		v4            bool
	}{{n.IPv4CIDR, n.IPv4Gateway, true}, {n.IPv6CIDR, n.IPv6Gateway, false}} {
		if entry.cidr != nil {
			ip, _, err := net.ParseCIDR(*entry.cidr)
			if err != nil || (ip.To4() != nil) != entry.v4 {
				return false
			}
		}
		if entry.gateway != nil {
			ip := net.ParseIP(*entry.gateway)
			if ip == nil || (ip.To4() != nil) != entry.v4 || entry.cidr == nil {
				return false
			}
		}
	}
	return true
}
func DecodeCreateBindingBody(c Command) (CreateBindingBody, error) {
	var b CreateBindingBody
	if strictBindingObject(c.Body, &b) != nil || b.Version != 1 {
		return b, codedError(CodeValidation)
	}
	for _, s := range []string{c.ClusterUID, c.ProjectUID, c.PrincipalID, c.OwnerID, c.ManagementKey, c.RequestID, c.SessionID} {
		if s == "" || len(s) > MaxStringBytes {
			return b, codedError(CodeValidation)
		}
	}
	if c.Session == 0 || c.Session > math.MaxInt64 || c.Generation >= math.MaxInt64 || c.ExpectedRevision != 0 || c.ResourceUID != "" {
		return b, codedError(CodeValidation)
	}
	v := b.Desired
	if safename.ValidateVMName(v.Name) != nil || v.CPU == 0 || v.MemoryMiB == 0 || v.MemoryMiB > math.MaxInt64 || !validPlacement(v.Placement, c.ClusterUID) || !validReferenceInput(v.Image, c.ClusterUID, "image") {
		return b, codedError(CodeValidation)
	}
	if v.MaxCPU != nil && *v.MaxCPU < v.CPU {
		return b, codedError(CodeValidation)
	}
	if v.MemoryHotplugMaxMiB != nil && (*v.MemoryHotplugMaxMiB < v.MemoryMiB || *v.MemoryHotplugMaxMiB > math.MaxInt64) {
		return b, codedError(CodeValidation)
	}
	if v.RequestedState != "" && v.RequestedState != "running" && v.RequestedState != "stopped" {
		return b, codedError(CodeValidation)
	}
	seen := map[string]bool{}
	for _, disk := range v.Disks {
		if disk.Key == "" || seen[disk.Key] || disk.SizeBytes == 0 || disk.SizeBytes > math.MaxInt64 || !validReferenceInput(disk.Pool, c.ClusterUID, "pool") || !validReferenceInput(disk.Image, c.ClusterUID, "image") || (disk.Bus != "" && disk.Bus != "virtio" && disk.Bus != "scsi" && disk.Bus != "sata") {
			return b, codedError(CodeValidation)
		}
		seen[disk.Key] = true
	}
	seen = map[string]bool{}
	for _, nic := range v.NICs {
		if seen[nic.Key] || !validNIC(nic, c.ClusterUID) {
			return b, codedError(CodeValidation)
		}
		seen[nic.Key] = true
	}
	return b, nil
}
