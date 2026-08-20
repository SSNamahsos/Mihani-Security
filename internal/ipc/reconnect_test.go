package ipc

import (
	"net"
	"testing"
	"time"
)

func TestClientReconnectsAfterServerRestart(t *testing.T) {
	pipe := `\\.\pipe\MihaniSecurityTestReconnect`

	allowed := []string{`C:\test\MihaniSecurity.exe`}
	resolver := func(c net.Conn) (string, error) { return allowed[0], nil }

	var active *Server
	handler := func(c net.Conn, m Msg) {
		if active != nil {
			_ = active.Send(c, Reply(m, MsgAck, nil))
		}
	}

	srv := NewServer(pipe, handler)
	srv.SetAllowedClientPaths(allowed)
	srv.SetClientResolver(resolver)
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	active = srv

	cli := NewClient(pipe, nil)
	if err := cli.ConnectRetry(2 * time.Second); err != nil {
		t.Fatalf("initial connect: %v", err)
	}
	if !cli.Connected() {
		t.Fatal("expected connected after initial connect")
	}

	srv.Close()
	deadline := time.Now().Add(3 * time.Second)
	for cli.Connected() && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if cli.Connected() {
		t.Fatal("client should be disconnected after server close")
	}
	if _, err := cli.Call(Msg{Type: MsgStatusGet, ID: newMsgID()}, 500*time.Millisecond); err == nil {
		t.Fatal("call while disconnected should fail")
	}

	srv2 := NewServer(pipe, handler)
	srv2.SetAllowedClientPaths(allowed)
	srv2.SetClientResolver(resolver)
	if err := srv2.Listen(); err != nil {
		t.Fatalf("relisten: %v", err)
	}
	active = srv2

	if err := cli.ConnectRetry(3 * time.Second); err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	if !cli.Connected() {
		t.Fatal("expected reconnected")
	}
	if _, err := cli.Call(Msg{Type: MsgStatusGet, ID: newMsgID()}, 2*time.Second); err != nil {
		t.Fatalf("call after reconnect: %v", err)
	}
	cli.Close()
	srv2.Close()
}