package compose

import "testing"

// Describe says what will actually be probed: the resolved target (the VM's
// address in place of a VM-relative host), the effective interval, timeout,
// retries and action — defaults included — and whether the type was inferred.
func TestHealthCheckDef_Describe(t *testing.T) {
	for _, c := range []struct{ hc, want string }{
		{"      target: \"22\"\n",
			"tcp (inferred) <vm address>:22 every 10s, timeout 5s, 3 retries, then restart"},
		{"      type: tcp\n      target: \"db.internal:5432\"\n      interval: 30s\n      timeout: 2s\n      retries: 1\n      action: alert\n",
			"tcp db.internal:5432 every 30s, timeout 2s, 1 retry, then alert"},
		{"      type: http\n      target: \":8080/health\"\n      action: migrate\n",
			"http GET http://<vm address>:8080/health every 10s, timeout 5s, 3 retries, then migrate"},
		{"      target: \"https://localhost:8443/ready\"\n",
			"https (inferred) GET https://<vm address>:8443/ready every 10s, timeout 5s, 3 retries, then restart"},
		{"      type: ping\n",
			"ping <vm address> every 10s, timeout 5s, 3 retries, then restart"},
		{"      type: exec\n      target: \"systemctl is-active nginx\"\n",
			`exec "systemctl is-active nginx" in the guest every 10s, timeout 5s, 3 retries, then restart`},
		{"      type: tcp\n      target: \"22\"\n      interval: 1ms\n",
			"tcp <vm address>:22 every 10s (1ms is below the checker's 10s sweep), timeout 5s, 3 retries, then restart"},
	} {
		f, err := ParseBytes([]byte(hcVM + c.hc))
		if err != nil {
			t.Errorf("healthcheck\n%s\nrefused: %v", c.hc, err)
			continue
		}
		if got := f.VMs["web"].HealthCheck.Describe(); got != c.want {
			t.Errorf("healthcheck\n%s\nDescribe() = %q\n        want %q", c.hc, got, c.want)
		}
	}
}
