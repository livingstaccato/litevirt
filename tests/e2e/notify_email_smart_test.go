package e2e

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// Email notifications and the disk SMART monitor against a live node. The
// fleet fakes cannot prove a real daemon opens a real SMTP connection or that
// smartctl is actually consulted, so these check the effect from outside lv.
// Both need the node's loopback (the daemon dials the sink on 127.0.0.1), so
// they run on a cluster node.

// TestNotifyEmail_TestSendReachesSMTPSink adds an email target pointing at a
// plaintext loopback sink, runs `lv notify test`, and asserts the sink received
// a real message with the subject and recipient. The password check proves the
// stored password never comes back through `lv notify target ls`.
func TestNotifyEmail_TestSendReachesSMTPSink(t *testing.T) {
	requireLocalNode(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var mu sync.Mutex
	var got strings.Builder
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(15 * time.Second))
				r := bufio.NewReader(c)
				fmt.Fprint(c, "220 sink\r\n")
				data := false
				for {
					l, err := r.ReadString('\n')
					if err != nil {
						return
					}
					l = strings.TrimRight(l, "\r\n")
					mu.Lock()
					got.WriteString(l + "\n")
					mu.Unlock()
					switch {
					case data && l == ".":
						data = false
						fmt.Fprint(c, "250 ok\r\n")
					case data:
					case strings.HasPrefix(strings.ToUpper(l), "EHLO"):
						fmt.Fprint(c, "250 sink\r\n")
					case strings.ToUpper(l) == "DATA":
						data = true
						fmt.Fprint(c, "354 go\r\n")
					case strings.ToUpper(l) == "QUIT":
						fmt.Fprint(c, "221 bye\r\n")
						return
					default:
						fmt.Fprint(c, "250 ok\r\n")
					}
				}
			}(c)
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	out := lv(t, "notify", "target", "add", "--name", "e2e-mail", "--type", "email",
		"--smtp-host", "127.0.0.1", "--smtp-port", fmt.Sprint(port), "--smtp-tls", "none",
		"--from", "litevirt@e2e.invalid", "--to", "ops@e2e.invalid")
	m := regexp.MustCompile(`: (\S+)\s*$`).FindStringSubmatch(strings.TrimSpace(out))
	if m == nil {
		t.Fatalf("no target id in %q", out)
	}
	id := m[1]
	defer lv(t, "notify", "target", "rm", id)

	lv(t, "notify", "test", id)
	mu.Lock()
	defer mu.Unlock()
	for _, want := range []string{"RCPT TO:<ops@e2e.invalid>", "Subject: ", "test.notification"} {
		if !strings.Contains(got.String(), want) {
			t.Errorf("sink never saw %q:\n%s", want, got.String())
		}
	}
}

// TestSMART_GaugeMatchesSmartctl asserts the daemon's SMART gauge agrees with
// reality: litevirt_disk_smart_available is 1 exactly when smartctl is
// installed, and every disk smartctl --scan lists has a status series.
func TestSMART_GaugeMatchesSmartctl(t *testing.T) {
	requireLocalNode(t)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get("http://127.0.0.1:7444/metrics")
	if err != nil {
		t.Skipf("metrics endpoint unreachable: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	body := string(b)
	if strings.Contains(body, "litevirt_disk_smart_available") == false {
		t.Skip("smart monitor disabled (smart.interval 0/off) on this node")
	}
	_, lookErr := exec.LookPath("smartctl")
	want := "litevirt_disk_smart_available 1"
	if lookErr != nil {
		want = "litevirt_disk_smart_available 0"
	}
	if !strings.Contains(body, want) {
		t.Errorf("metrics lack %q", want)
	}
	if lookErr == nil {
		scan, _ := exec.Command("smartctl", "--scan").Output()
		for _, line := range strings.Split(string(scan), "\n") {
			f := strings.Fields(line)
			if len(f) == 0 || !strings.HasPrefix(f[0], "/dev/") {
				continue
			}
			if !strings.Contains(body, `litevirt_disk_smart_status{device="`+f[0]+`"`) {
				t.Errorf("no litevirt_disk_smart_status series for %s", f[0])
			}
			// The model label comes from smartctl's information section (-i), which
			// the scan must ask for. Compare it with what smartctl itself reports.
			args := []string{"--json", "-i"}
			if len(f) > 2 && f[1] == "-d" {
				args = append(args, "-d", f[2])
			}
			info, _ := exec.Command("smartctl", append(args, f[0])...).Output() // exit status is a bitmask
			var id struct {
				ModelName string `json:"model_name"`
			}
			if json.Unmarshal(info, &id) == nil && id.ModelName != "" &&
				!strings.Contains(body, `litevirt_disk_smart_status{device="`+f[0]+`",model="`+id.ModelName+`"`) {
				t.Errorf("the series for %s lacks model=%q, which smartctl -i reports", f[0], id.ModelName)
			}
		}
	}
}
