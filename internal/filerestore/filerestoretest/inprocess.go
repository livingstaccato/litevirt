// Package filerestoretest runs the file-restore agent in the test process.
//
// FOR TESTS ONLY. It reads a directory or parses an archive on the host,
// which is exactly what production never does: there the agent runs inside
// a restore VM. Production code must not import it
// (TestNoProductionImport in this package enforces that).
package filerestoretest

import (
	"fmt"
	"net"

	"github.com/litevirt/litevirt/internal/filerestore"
	"github.com/litevirt/litevirt/internal/filerestore/agent"
	"github.com/litevirt/litevirt/internal/filerestore/wire"
)

// Nonce is the nonce every in-process agent answers OpHello with.
const Nonce = "in-process"

// Session is a Client to an in-process agent.
type Session struct {
	*filerestore.Client
	done chan struct{}
}

// Open serves an agent in this process over an in-memory pipe: a container
// archive parsed from dev (KindArchive), or dir as volume "vda1" (KindFS).
func Open(dev filerestore.BlockDevice, kind, dir string) (*Session, error) {
	vols := map[string]agent.Volume{}
	switch kind {
	case wire.KindArchive:
		v, name, err := agent.IndexArchive(dev, dev.Size())
		if err != nil {
			return nil, err
		}
		vols[name] = v
	case wire.KindFS:
		vols["vda1"] = agent.NewDirVolume(dir, "ext4")
	default:
		return nil, fmt.Errorf("kind %q", kind)
	}
	return Serve(agent.NewServer(vols, Nonce))
}

// Serve connects a Client to srv over an in-memory pipe and checks the
// hello.
func Serve(srv *agent.Server) (*Session, error) {
	host, guest := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = srv.ServeConn(guest)
		guest.Close()
	}()
	s := &Session{Client: filerestore.NewClient(host), done: done}
	if err := s.Client.Hello(Nonce); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// Close ends the session.
func (s *Session) Close() {
	s.Client.Close()
	<-s.done
}
