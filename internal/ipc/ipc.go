package ipc

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	winio "github.com/Microsoft/go-winio"

	"github.com/mihanistudio/mihanisecurity/internal/events"
)

const PipeName = `\\.\pipe\MihaniSecurity`

const pipeSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"

const writeTimeout = 3 * time.Second

const maxLine = 4 << 20

type Msg struct {
	Type    string          `json:"type"`
	ID      string          `json:"id,omitempty"`
	Time    time.Time       `json:"time"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

const (
	MsgStatus       = "status"
	MsgVerdict      = "verdict"
	MsgEvent        = "event"
	MsgScanProgress = "scan_progress"
	MsgScanResult   = "scan_result"
	MsgError        = "error"
	MsgAck          = "ack"
	MsgPong         = "pong"

	MsgStatusGet         = "status_get"
	MsgQuarantineList    = "quarantine_list"
	MsgSettingsGet       = "settings_get"
	MsgSettingsSet       = "settings_set"
	MsgScanNow           = "scan_now"
	MsgScanCancel        = "scan_cancel"
	MsgQuarantineDelete  = "quarantine_delete"
	MsgQuarantineRestore = "quarantine_restore"
	MsgSignaturesReload  = "signatures_reload"
	MsgSignaturesImport  = "signatures_import"
	MsgToggleRealTime    = "toggle_realtime"
	MsgWscRegister       = "wsc_register"
	MsgLogTail           = "log_tail"
	MsgPing              = "ping"
	MsgVerdictAction     = "verdict_action"
)

type Server struct {
	path     string
	listener net.Listener
	mu       sync.Mutex
	clients  map[net.Conn]struct{}
	closed   bool
	onMsg    func(c net.Conn, m Msg)
	allowed  []string
	authFn   func(c net.Conn) (string, error)
}

func NewServer(pipeName string, onMsg func(c net.Conn, m Msg)) *Server {
	return &Server{path: pipeName, onMsg: onMsg, clients: map[net.Conn]struct{}{}}
}

func (s *Server) SetAllowedClientPaths(paths []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.allowed = append([]string(nil), paths...)
}

func (s *Server) SetClientResolver(fn func(c net.Conn) (string, error)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authFn = fn
}

func (s *Server) Listen() error {
	l, err := winio.ListenPipe(s.path, &winio.PipeConfig{
		SecurityDescriptor: pipeSDDL,
		MessageMode:        false,
		InputBufferSize:    64 << 10,
		OutputBufferSize:   64 << 10,
	})
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.path, err)
	}
	s.mu.Lock()
	s.listener = l
	s.mu.Unlock()

	go s.accept(l)
	return nil
}

func (s *Server) accept(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed || errors.Is(err, winio.ErrPipeListenerClosed) || errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			c.Close()
			return
		}
		s.clients[c] = struct{}{}
		s.mu.Unlock()
		go s.serve(c)
	}
}

func (s *Server) serve(c net.Conn) {
	defer func() {
		s.mu.Lock()
		delete(s.clients, c)
		s.mu.Unlock()
		c.Close()
	}()

	s.mu.Lock()
	allowed := append([]string(nil), s.allowed...)
	authFn := s.authFn
	s.mu.Unlock()
	resolve := authFn
	if resolve == nil {
		resolve = clientImagePath
	}
	if allowed == nil {
		allowed = defaultAllowedPaths()
	}
	path, err := resolve(c)
	if err != nil || !isAllowedPath(path, allowed) {
		log.Printf("ipc: rejected client (path=%q err=%v)", path, err)
		return
	}

	rd := bufio.NewReaderSize(c, 64<<10)
	for {
		line, err := readLine(rd)
		if err != nil {
			return
		}
		if len(line) == 0 {
			continue
		}
		var m Msg
		if err := json.Unmarshal(line, &m); err != nil {
			_ = s.Send(c, Msg{Type: MsgError, Payload: Encode(map[string]string{"error": "malformed message"})})
			continue
		}
		if s.onMsg != nil {
			s.onMsg(c, m)
		}
	}
}

func readLine(rd *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		chunk, err := rd.ReadSlice('\n')
		buf = append(buf, chunk...)
		if len(buf) > maxLine {
			return nil, errors.New("message too large")
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			return nil, err
		}
		return buf, nil
	}
}

func (s *Server) Broadcast(m Msg) error {
	s.mu.Lock()
	conns := make([]net.Conn, 0, len(s.clients))
	for c := range s.clients {
		conns = append(conns, c)
	}
	s.mu.Unlock()

	var firstErr error
	for _, c := range conns {
		if err := s.write(c, m); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (s *Server) Send(c net.Conn, m Msg) error {
	if c == nil {
		return errors.New("no client")
	}
	return s.write(c, m)
}

func (s *Server) write(c net.Conn, m Msg) error {
	if m.Time.IsZero() {
		m.Time = time.Now()
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_ = c.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, err = c.Write(b)
	if err != nil {
		c.Close()
	}
	return err
}

func (s *Server) Clients() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.clients)
}

func (s *Server) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	l := s.listener
	conns := make([]net.Conn, 0, len(s.clients))
	for c := range s.clients {
		conns = append(conns, c)
	}
	s.mu.Unlock()

	if l != nil {
		l.Close()
	}
	for _, c := range conns {
		c.Close()
	}
}

type Client struct {
	path    string
	onMsg   func(m Msg)
	mu      sync.Mutex
	conn    net.Conn
	closed  bool
	pending map[string]chan Msg

	OnDisconnect func()
}

func NewClient(pipeName string, onMsg func(m Msg)) *Client {
	return &Client{path: pipeName, onMsg: onMsg, pending: map[string]chan Msg{}}
}

func (c *Client) Connect() error {
	timeout := 2 * time.Second
	conn, err := winio.DialPipe(c.path, &timeout)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.conn = conn
	c.closed = false
	c.mu.Unlock()
	go c.read(conn)
	return nil
}

func (c *Client) ConnectRetry(dur time.Duration) error {
	deadline := time.Now().Add(dur)
	var last error
	for {
		if err := c.Connect(); err == nil {
			return nil
		} else {
			last = err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("service unavailable: %w", last)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func (c *Client) Connected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn != nil && !c.closed
}

func (c *Client) read(conn net.Conn) {
	rd := bufio.NewReaderSize(conn, 64<<10)
	for {
		line, err := readLine(rd)
		if err != nil {
			c.drop(conn)
			return
		}
		var m Msg
		if err := json.Unmarshal(line, &m); err != nil {
			continue
		}

		if m.ID != "" {
			c.mu.Lock()
			ch, ok := c.pending[m.ID]
			if ok {
				delete(c.pending, m.ID)
			}
			c.mu.Unlock()
			if ok {
				ch <- m
				continue
			}
		}
		if c.onMsg != nil {
			c.onMsg(m)
		}
	}
}

func (c *Client) drop(conn net.Conn) {
	c.mu.Lock()
	if c.conn == conn {
		c.conn = nil
	}
	pending := c.pending
	c.pending = map[string]chan Msg{}
	notify := c.OnDisconnect
	c.mu.Unlock()

	conn.Close()
	for _, ch := range pending {
		close(ch)
	}
	if notify != nil {
		notify()
	}
}

func (c *Client) Send(m Msg) error {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return errors.New("not connected")
	}
	if m.Time.IsZero() {
		m.Time = time.Now()
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, err = conn.Write(b)
	return err
}

func (c *Client) Call(m Msg, timeout time.Duration) (Msg, error) {
	if m.ID == "" {
		m.ID = newMsgID()
	}
	ch := make(chan Msg, 1)
	c.mu.Lock()
	if c.conn == nil {
		c.mu.Unlock()
		return Msg{}, errors.New("not connected")
	}
	c.pending[m.ID] = ch
	c.mu.Unlock()

	if err := c.Send(m); err != nil {
		c.mu.Lock()
		delete(c.pending, m.ID)
		c.mu.Unlock()
		return Msg{}, err
	}
	select {
	case rep, ok := <-ch:
		if !ok {
			return Msg{}, errors.New("disconnected")
		}
		if rep.Type == MsgError {
			return rep, fmt.Errorf("service error: %s", decodeError(rep.Payload))
		}
		return rep, nil
	case <-time.After(timeout):
		c.mu.Lock()
		delete(c.pending, m.ID)
		c.mu.Unlock()
		return Msg{}, errTimeout
	}
}

func (c *Client) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	conn := c.conn
	c.conn = nil
	c.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
}

var errTimeout = errors.New("timeout")

func IsTimeout(err error) bool { return errors.Is(err, errTimeout) }

func Encode(v interface{}) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}

func Reply(req Msg, typ string, payload interface{}) Msg {
	return Msg{Type: typ, ID: req.ID, Payload: Encode(payload)}
}

func Ack(req Msg) Msg { return Msg{Type: MsgAck, ID: req.ID} }

func ErrorReply(req Msg, err error) Msg {
	text := "unknown error"
	if err != nil {
		text = err.Error()
	}
	return Msg{Type: MsgError, ID: req.ID, Payload: Encode(map[string]string{"error": text})}
}

func decodeError(payload json.RawMessage) string {
	var m map[string]string
	if err := json.Unmarshal(payload, &m); err == nil && m["error"] != "" {
		return m["error"]
	}
	return "unknown error"
}

func newMsgID() string { return fmt.Sprintf("%d", time.Now().UnixNano()) }

func StatusMsg(s events.Status) Msg { return Msg{Type: MsgStatus, Payload: Encode(s)} }

func VerdictMsg(v events.Verdict) Msg { return Msg{Type: MsgVerdict, Payload: Encode(v)} }

func EventMsg(e events.Event) Msg { return Msg{Type: MsgEvent, Payload: Encode(e)} }

func ScanProgressMsg(p events.ScanProgress) Msg {
	return Msg{Type: MsgScanProgress, Payload: Encode(p)}
}

func ScanResultMsg(r *ScanResult) Msg { return Msg{Type: MsgScanResult, Payload: Encode(r)} }
