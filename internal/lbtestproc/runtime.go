// Package lbtestproc supplies an owned process runtime for private LB fixtures.
package lbtestproc

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type child struct {
	cmd  *exec.Cmd
	done chan error
}
type Runtime struct {
	mu        sync.Mutex
	t         testing.TB
	Dir       string
	installed bool
	once      sync.Once
	Looks     int
	children  map[string]*child
	pids      map[string]string
	Starts    map[string]int
}

func New(t testing.TB, installed bool) *Runtime {
	r := &Runtime{t: t, Dir: t.TempDir(), installed: installed, children: map[string]*child{}, pids: map[string]string{}, Starts: map[string]int{}}
	t.Cleanup(r.Close)
	return r
}
func (r *Runtime) record(bin string, args ...string) {
	f, e := os.OpenFile(filepath.Join(r.Dir, bin+".calls"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		r.t.Fatal(e)
	}
	defer f.Close()
	fmt.Fprintln(f, strings.Join(args, " "))
}
func (r *Runtime) start(bin, cfg, pid string) error {
	key := bin + ":" + cfg
	r.stop(key)
	cmd := exec.Command("/bin/cat")
	// Cmd owns the sole stdin pipe writer in this process. Its close-on-exec
	// writer cannot survive in sibling commands; owner death gives cat EOF.
	// Start failure and the actual Wait both close the owned pipe ends.
	if _, e := cmd.StdinPipe(); e != nil {
		return e
	}
	if e := cmd.Start(); e != nil {
		return e
	}
	c := &child{cmd: cmd, done: make(chan error, 1)}
	go func() { c.done <- cmd.Wait(); close(c.done) }()
	r.children[key] = c
	r.Starts[bin]++
	if pid != "" {
		r.pids[pid] = key
		return os.WriteFile(pid, []byte(fmt.Sprint(cmd.Process.Pid)), 0600)
	}
	return nil
}
func (r *Runtime) stop(key string) {
	if c := r.children[key]; c != nil {
		_ = c.cmd.Process.Kill()
		select {
		case <-c.done:
		case <-time.After(5 * time.Second):
			r.t.Fatalf("owned child %d did not join", c.cmd.Process.Pid)
		}
		delete(r.children, key)
	}
}
func (r *Runtime) Run(ctx context.Context, bin string, args ...string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	r.record(bin, args...)
	switch bin {
	case "sysctl":
		if len(args) != 2 || args[1] != "net.ipv4.ip_nonlocal_bind=1" {
			return nil, fmt.Errorf("unexpected sysctl %v", args)
		}
	case "haproxy":
		if len(args) != 3 || args[0] != "-c" {
			return nil, fmt.Errorf("unexpected validator %v", args)
		}
		if _, e := os.ReadFile(args[2]); e != nil {
			return nil, e
		}
	case "ip":
		if len(args) != 5 || args[0] != "addr" || args[1] != "del" || args[3] != "dev" || args[4] == "" {
			return nil, fmt.Errorf("unexpected private VIP deletion %v", args)
		}
		if _, _, err := net.ParseCIDR(args[2]); err != nil {
			return nil, err
		}
		// The fixture has no kernel VIP. Its deletion observation must follow
		// actual exit/reap of every owned keepalived child, never just a signal.
		for key, c := range r.children {
			if strings.HasPrefix(key, "keepalived:") {
				select {
				case <-c.done:
				case <-time.After(5 * time.Second):
					return nil, fmt.Errorf("VIP deletion before owned keepalived exit: %s", key)
				}
			}
		}
	case "conntrackd":
		if len(args) != 3 || args[0] != "-C" || args[2] != "-d" {
			return nil, fmt.Errorf("unexpected conntrackd %v", args)
		}
		return nil, r.start(bin, args[1], "")
	default:
		return nil, fmt.Errorf("host command refused: %s", bin)
	}
	return nil, nil
}
func (r *Runtime) ConntrackdInstalled() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.once.Do(func() { r.Looks++ })
	return r.installed
}
func (r *Runtime) ConfigAlive(bin, cfg string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	c := r.children[bin+":"+cfg]
	if c == nil {
		return false
	}
	select {
	case <-c.done:
		return false
	default:
		return true
	}
}
func (r *Runtime) StopConfig(bin, cfg string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stop(bin + ":" + cfg)
}
func (r *Runtime) PIDAlive(pid string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	c := r.children[r.pids[pid]]
	if c == nil {
		return false
	}
	select {
	case <-c.done:
		return false
	default:
		return true
	}
}
func (r *Runtime) StartHAProxy(cfg, pid string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.record("haproxy", "-f", cfg, "-p", pid)
	return r.start("haproxy", cfg, pid)
}
func (r *Runtime) StartKeepalived(cfg, pid string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.record("keepalived", "-f", cfg, "-p", pid)
	return r.start("keepalived", cfg, pid)
}
func (r *Runtime) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k := range r.children {
		r.stop(k)
	}
	r.t.Log("private LB process runtime: all owned children killed and reaped")
}
