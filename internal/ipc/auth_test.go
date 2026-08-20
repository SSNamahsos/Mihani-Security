package ipc

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

func TestIsAllowedPath(t *testing.T) {
	allowed := []string{`C:\Program Files\MihaniSecurity\MihaniSecurity.exe`}
	cases := []struct {
		path string
		ok   bool
	}{
		{`C:\Program Files\MihaniSecurity\MihaniSecurity.exe`, true},
		{`c:\program files\mihaniSecurity\MihaniSecurity.exe`, true},
		{`C:\evil\stealer.exe`, false},
		{`C:\Program Files\MihaniSecurity\evil.exe`, false},
		{``, false},
		{`C:\Program Files\MihaniSecurity\MihaniSecurity.exe2`, false},
	}
	for _, c := range cases {
		if got := isAllowedPath(c.path, allowed); got != c.ok {
			t.Errorf("isAllowedPath(%q) = %v, want %v", c.path, got, c.ok)
		}
	}
}

func testPipe(t *testing.T) string {
	return fmt.Sprintf(`\\.\pipe\mihani-test-%d-%d`, os.Getpid(), time.Now().UnixNano())
}

func TestServerRejectsUnauthorizedClient(t *testing.T) {
	name := testPipe(t)
	var s *Server
	s = NewServer(name, func(c net.Conn, m Msg) {
		_ = s.Send(c, Reply(m, MsgPong, nil))
	})
	s.SetClientResolver(func(c net.Conn) (string, error) { return `C:\evil\stealer.exe`, nil })
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	cl := NewClient(name, nil)
	if err := cl.Connect(); err != nil {
		t.Fatal(err)
	}
	defer cl.Close()

	_, err := cl.Call(Msg{Type: MsgPing}, 800*time.Millisecond)
	if err == nil {
		t.Fatal("unauthorized client received a reply")
	}
	if s.Clients() != 0 {
		t.Fatalf("unauthorized client still registered: %d clients", s.Clients())
	}
}

func TestServerAcceptsAuthorizedClient(t *testing.T) {
	name := testPipe(t)
	var s *Server
	s = NewServer(name, func(c net.Conn, m Msg) {
		_ = s.Send(c, Reply(m, MsgPong, nil))
	})
	s.SetClientResolver(func(c net.Conn) (string, error) { return `C:\Program Files\MihaniSecurity\MihaniSecurity.exe`, nil })
	s.SetAllowedClientPaths([]string{`C:\Program Files\MihaniSecurity\MihaniSecurity.exe`})
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	cl := NewClient(name, nil)
	if err := cl.Connect(); err != nil {
		t.Fatal(err)
	}
	defer cl.Close()

	rep, err := cl.Call(Msg{Type: MsgPing}, 2*time.Second)
	if err != nil {
		t.Fatalf("authorized client failed: %v", err)
	}
	if rep.Type != MsgPong {
		t.Fatalf("expected pong, got %s", rep.Type)
	}
	if s.Clients() != 1 {
		t.Fatalf("expected 1 client, got %d", s.Clients())
	}
}

func TestServerResolverErrorRejects(t *testing.T) {
	name := testPipe(t)
	s := NewServer(name, func(c net.Conn, m Msg) {})
	s.SetClientResolver(func(c net.Conn) (string, error) { return "", fmt.Errorf("boom") })
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	cl := NewClient(name, nil)
	if err := cl.Connect(); err != nil {
		t.Fatal(err)
	}
	defer cl.Close()

	if _, err := cl.Call(Msg{Type: MsgPing}, 800*time.Millisecond); err == nil {
		t.Fatal("client with unresolved identity received a reply")
	}
}
