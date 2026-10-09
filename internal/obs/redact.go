package obs

import (
	"context"
	"log/slog"
	"strings"
)

// redactedValue replaces the value of an attribute whose key names secret
// material.
const redactedValue = "[REDACTED]"

// secretKeys are attribute keys whose value is secret material, compared
// case-insensitively against the key's last dotted segment.
var secretKeys = map[string]bool{
	"password": true, "passwd": true, "pass": true, "pwd": true,
	"token": true, "secret": true, "bearer": true, "authorization": true,
	"key": true, "keyring": true, "credential": true, "credentials": true,
	"apikey": true, "api_key": true, "private_key": true, "secret_key": true,
	"access_key": true, "ipmi_pass": true, "ipmi_password": true,
}

// secretKeySuffixes extend secretKeys to compound names (client_secret,
// session_token, bmc_password, ...).
var secretKeySuffixes = []string{
	"_password", "_passwd", "_pass", "_secret", "_token", "_bearer",
	"_keyring", "_credential", "_credentials", "_apikey", "_api_key", "_private_key",
}

// isSecretKey reports whether an attribute key names secret material.
func isSecretKey(k string) bool {
	k = strings.ToLower(k)
	if i := strings.LastIndexByte(k, '.'); i >= 0 {
		k = k[i+1:]
	}
	if secretKeys[k] {
		return true
	}
	for _, s := range secretKeySuffixes {
		if strings.HasSuffix(k, s) {
			return true
		}
	}
	return false
}

// redactHandler masks, by key, attributes that carry secret material before
// any other handler sees them. It runs in every mode, whatever the vendor's
// value-pattern sanitizer (PROVIDE_LOG_SANITIZE) is set to: that one is off by
// default because it also rewrites litevirt's non-secret lines, so the keys
// below are the guarantee that a password, token or key never reaches the
// journal or an exporter as a field value. Non-secret identifiers that used to
// be logged under such keys (capability names, lease and claim keys) are
// logged under descriptive keys instead.
type redactHandler struct{ next slog.Handler }

// NewRedactHandler wraps next in the secret-key masking. Setup's pipeline
// uses it, and so does the CLI's bootstrap logger (cmd/litevirt), which every
// one-shot command and the daemon before Setup log through.
func NewRedactHandler(next slog.Handler) slog.Handler { return redactHandler{next: next} }

func (h redactHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.next.Enabled(ctx, l)
}

func (h redactHandler) Handle(ctx context.Context, r slog.Record) error {
	nr := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		nr.AddAttrs(redactAttr(a))
		return true
	})
	return h.next.Handle(ctx, nr)
}

func (h redactHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		out[i] = redactAttr(a)
	}
	return redactHandler{next: h.next.WithAttrs(out)}
}

func (h redactHandler) WithGroup(name string) slog.Handler {
	return redactHandler{next: h.next.WithGroup(name)}
}

func redactAttr(a slog.Attr) slog.Attr {
	if isSecretKey(a.Key) {
		return slog.String(a.Key, redactedValue)
	}
	v := a.Value.Resolve()
	if v.Kind() == slog.KindGroup {
		g := v.Group()
		out := make([]any, len(g))
		for i, ga := range g {
			out[i] = redactAttr(ga)
		}
		return slog.Group(a.Key, out...)
	}
	return slog.Attr{Key: a.Key, Value: v}
}
