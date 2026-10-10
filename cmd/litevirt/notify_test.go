package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildTargetConfig_Email(t *testing.T) {
	cfg, err := buildTargetConfig("email", "", emailTargetFlags{host: "smtp.example.com", from: "lv@example.com", to: []string{"a@x.y", "b@x.y"}, user: "u", passwordFile: "-", port: 587}, strings.NewReader("s3cret\n"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(cfg), &m); err != nil {
		t.Fatal(err)
	}
	if m["password"] != "s3cret" || m["host"] != "smtp.example.com" || m["username"] != "u" {
		t.Errorf("config = %s", cfg)
	}
	if _, ok := m["tls_skip_verify"]; ok {
		t.Error("tls_skip_verify must be absent unless asked for")
	}
}

func TestBuildTargetConfig_Errors(t *testing.T) {
	if _, err := buildTargetConfig("email", "", emailTargetFlags{host: "h"}, nil); err == nil {
		t.Error("email without from/to accepted")
	}
	if _, err := buildTargetConfig("email", "http://x", emailTargetFlags{host: "h", from: "a@b.c", to: []string{"c@d.e"}}, nil); err == nil {
		t.Error("--url on an email target accepted")
	}
	if _, err := buildTargetConfig("webhook", "", emailTargetFlags{}, nil); err == nil {
		t.Error("webhook without url accepted")
	}
	if _, err := buildTargetConfig("email", "", emailTargetFlags{host: "h", from: "a@b.c", to: []string{"c@d.e"}, passwordFile: "-"}, strings.NewReader("\n")); err == nil {
		t.Error("empty password accepted")
	}
	cfg, err := buildTargetConfig("slack", "https://hooks/x", emailTargetFlags{}, nil)
	if err != nil || cfg != `{"url":"https://hooks/x"}` {
		t.Errorf("slack config = %q, %v", cfg, err)
	}
}
