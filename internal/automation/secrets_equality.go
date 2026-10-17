package automation

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

// RawBootstrapIntent preserves message presence independently of file presence.
type RawBootstrapIntent struct {
	Present                           bool
	UserData, Metadata, NetworkConfig []byte
}

// IntentScope is the stable original request namespace and method, not mutable
// effective defaults, operation IDs, wrapping facts or session credentials.
type IntentScope struct{ ClusterUID, Namespace, Method string }

// BootstrapEqualityKey is independent of age identities and file keys. Import
// only independently generated 32-byte key material from a custody provider.
type BootstrapEqualityKey struct {
	epoch    string
	material [32]byte
}

var errBootstrapEqualityUnavailable = errors.New("bootstrap equality key unavailable")
var errBootstrapIntent = errors.New("invalid bootstrap intent")

// NewBootstrapEqualityKey imports independently generated secret material. It
// copies the key and does not enroll, persist, activate or certify its epoch.
func NewBootstrapEqualityKey(epoch string, material []byte) (BootstrapEqualityKey, error) {
	if !secretStringValid(epoch) || len(material) != 32 {
		return BootstrapEqualityKey{}, errBootstrapEqualityUnavailable
	}
	key := BootstrapEqualityKey{epoch: epoch}
	copy(key.material[:], material)
	return key, nil
}

// IntentTag requires the exact historical epoch from the original receipt. A
// missing or different key epoch is unavailable; there is no active-key fallback.
// The tag and epoch are private command facts and must never enter public output.
func (key BootstrapEqualityKey) IntentTag(epoch string, scope IntentScope, raw RawBootstrapIntent) ([]byte, error) {
	if key.epoch == "" || key.epoch != epoch {
		return nil, errBootstrapEqualityUnavailable
	}
	if !secretStringValid(scope.ClusterUID) || !secretStringValid(scope.Namespace) || !secretStringValid(scope.Method) || (!raw.Present && (raw.UserData != nil || raw.Metadata != nil || raw.NetworkConfig != nil)) {
		return nil, errBootstrapIntent
	}
	var frame secretFrame
	frame.raw([]byte("litevirt/automation/bootstrap-intent/v1\x00"))
	for _, s := range []string{epoch, scope.ClusterUID, scope.Namespace, scope.Method} {
		frame.text(s)
	}
	if raw.Present {
		frame.raw([]byte{1})
	} else {
		frame.raw([]byte{0})
	}
	for _, b := range [][]byte{raw.UserData, raw.Metadata, raw.NetworkConfig} {
		frame.optional(b)
	}
	if frame.invalid {
		return nil, errBootstrapIntent
	}
	mac := hmac.New(sha256.New, key.material[:])
	mac.Write(frame.Bytes())
	return mac.Sum(nil), nil
}

// CompareIntent uses constant-time tag comparison. Other immutable caller facts
// remain the responsibility of the canonical command and admission reducer.
func (key BootstrapEqualityKey) CompareIntent(epoch string, scope IntentScope, raw RawBootstrapIntent, tag []byte) (bool, error) {
	expected, err := key.IntentTag(epoch, scope, raw)
	if err != nil {
		return false, err
	}
	return hmac.Equal(expected, tag), nil
}
