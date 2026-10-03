package core

// Admin unix socket (SPEC §2.2, §12.1): the CLI's channel to a running node, gated by
// filesystem permissions alone. Protocol: one JSON request per connection —
// {"cmd": "...", "args": {...}} → {"ok": true, "data": ...} | {"ok": false, "error": "..."}.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// AdminSocketPath places the admin socket for a data dir. Unix socket paths are
// capped (~104 bytes on macOS, 108 on Linux); a deep data dir would fail to bind,
// so long paths deterministically fall back to the system temp dir, keyed by a hash
// of the data dir — server and CLI derive the same path independently.
func AdminSocketPath(dataDir string) string {
	p := filepath.Join(dataDir, "admin.sock")
	if len(p) <= 100 {
		return p
	}
	h := sha256.Sum256([]byte(dataDir))
	return filepath.Join(os.TempDir(), "hdtp-"+hex.EncodeToString(h[:6])+".sock")
}

type AdminHandler func(args map[string]string) (any, error)

type AdminServer struct {
	path     string
	mu       sync.RWMutex
	handlers map[string]AdminHandler
	ln       net.Listener
	lock     *os.File // held while this process serves the socket
}

func (s *AdminServer) releaseLock() {
	if s.lock != nil {
		_ = s.lock.Close() // closing the descriptor releases the flock
		s.lock = nil
	}
}

func NewAdminServer(path string) *AdminServer {
	return &AdminServer{path: path, handlers: map[string]AdminHandler{}}
}

func (s *AdminServer) Handle(cmd string, h AdminHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[cmd] = h
}

func (s *AdminServer) Start(ctx context.Context) error {
	// Several `serve` processes may share a data dir (core.AcquireServeLock), and they share its
	// socket path. The one holding the socket's own lock (<socket>.lock, flock, released when the
	// process dies) serves it; the others serve none (Serving reports false), and the admin
	// commands reach the holder. A socket file left without a holder is stale, from an unclean
	// shutdown, and the new holder replaces it.
	lf, err := os.OpenFile(s.path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("admin socket: %w", err)
	}
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lf.Close()
		return nil
	}
	s.lock = lf
	_ = os.Remove(s.path)
	ln, err := net.Listen("unix", s.path)
	if err != nil {
		s.releaseLock()
		return fmt.Errorf("admin socket: %w", err)
	}
	if err := os.Chmod(s.path, 0o600); err != nil {
		ln.Close()
		s.releaseLock()
		return fmt.Errorf("admin socket: %w", err)
	}
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
	go func() {
		<-ctx.Done()
		s.Close()
	}()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go s.serveConn(conn)
		}
	}()
	return nil
}

// Serving reports whether this process serves the admin socket; false when another process on the
// same data dir already did when Start ran.
func (s *AdminServer) Serving() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ln != nil
}

// Close stops serving the socket. It runs twice in `serve` (when the context ends, and deferred),
// and only the first does anything: by the second, another process may hold the socket, and its
// file is not this process's to remove.
func (s *AdminServer) Close() error {
	s.mu.Lock()
	ln := s.ln
	s.ln = nil
	s.mu.Unlock()
	if ln == nil {
		return nil
	}
	err := ln.Close()
	_ = os.Remove(s.path)
	s.releaseLock()
	return err
}

type adminRequest struct {
	Cmd  string            `json:"cmd"`
	Args map[string]string `json:"args"`
}

type adminResponse struct {
	OK    bool   `json:"ok"`
	Data  any    `json:"data,omitempty"`
	Error string `json:"error,omitempty"`
}

func (s *AdminServer) serveConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	var req adminRequest
	enc := json.NewEncoder(conn)
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		_ = enc.Encode(adminResponse{OK: false, Error: "bad request: " + err.Error()})
		return
	}
	s.mu.RLock()
	h, ok := s.handlers[req.Cmd]
	s.mu.RUnlock()
	if !ok {
		_ = enc.Encode(adminResponse{OK: false, Error: "unknown command: " + req.Cmd})
		return
	}
	data, err := h(req.Args)
	if err != nil {
		_ = enc.Encode(adminResponse{OK: false, Error: err.Error()})
		return
	}
	_ = enc.Encode(adminResponse{OK: true, Data: data})
}

// AdminCall is the client side: one command, one connection. out receives Data.
func AdminCall(path, cmd string, args map[string]string, out any) error {
	conn, err := net.DialTimeout("unix", path, 5*time.Second)
	if err != nil {
		return fmt.Errorf("admin socket: %w (is the node running?)", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if err := json.NewEncoder(conn).Encode(adminRequest{Cmd: cmd, Args: args}); err != nil {
		return fmt.Errorf("admin socket: %w", err)
	}
	var raw struct {
		OK    bool            `json:"ok"`
		Data  json.RawMessage `json:"data"`
		Error string          `json:"error"`
	}
	if err := json.NewDecoder(conn).Decode(&raw); err != nil {
		return fmt.Errorf("admin socket: %w", err)
	}
	if !raw.OK {
		return fmt.Errorf("%s", raw.Error)
	}
	if out != nil && len(raw.Data) > 0 {
		return json.Unmarshal(raw.Data, out)
	}
	return nil
}
