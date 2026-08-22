package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultLiveStreamAddr = "127.0.0.1:8788"
	liveProtocolLabel     = "smartcar-live-v1"
	livePollInterval      = 250 * time.Millisecond
	liveHeartbeatInterval = 1 * time.Second
)

type liveClient struct {
	conn net.Conn
	mu   sync.Mutex
}

type liveBridge struct {
	secret   []byte
	addr     string
	clients  map[*liveClient]struct{}
	clientsM sync.Mutex
	lastHash [32]byte
	lastSend time.Time
}

type liveHandshake struct {
	Type      string `json:"type,omitempty"`
	Challenge string `json:"challenge,omitempty"`
	Proof     string `json:"proof,omitempty"`
	Instance  string `json:"instance_id,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
}

type liveEnvelope struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}

func init() {
	if os.Getenv("SMARTCAR_GO_ENABLE_LIVE_STREAM") != "1" {
		return
	}
	go func() {
		if err := runLiveBridgeFromEnvironment(); err != nil {
			log.Printf("SmartCar live stream disabled: %v", err)
		}
	}()
}

func runLiveBridgeFromEnvironment() error {
	secret, err := loadAPISecret()
	if err != nil {
		return err
	}
	addr := strings.TrimSpace(os.Getenv("SMARTCAR_GO_LIVE_ADDR"))
	if addr == "" {
		addr = defaultLiveStreamAddr
	}
	if err := validateLiveStreamAddr(addr); err != nil {
		return err
	}
	bridge := &liveBridge{secret: append([]byte(nil), secret...), addr: addr, clients: make(map[*liveClient]struct{})}
	return bridge.run()
}

func validateLiveStreamAddr(addr string) error {
	host, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return fmt.Errorf("invalid SMARTCAR_GO_LIVE_ADDR: %w", err)
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil || !ip.IsLoopback() {
		return errors.New("SMARTCAR_GO_LIVE_ADDR must bind to a literal loopback address")
	}
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1024 || portNum > 65535 {
		return errors.New("SMARTCAR_GO_LIVE_ADDR must use a valid non-privileged port")
	}
	return nil
}

func liveProof(secret []byte, challenge string) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(liveProtocolLabel + ":" + challenge))
	return hex.EncodeToString(mac.Sum(nil))
}

func (b *liveBridge) run() error {
	listener, err := net.Listen("tcp", b.addr)
	if err != nil {
		return fmt.Errorf("listen on authenticated live socket %s: %w", b.addr, err)
	}
	defer listener.Close()
	log.Printf("SmartCar live stream listening on %s (authenticated loopback socket)", b.addr)
	go b.broadcastLoop()
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		if !isLoopbackRemote(conn.RemoteAddr().String()) {
			_ = conn.Close()
			continue
		}
		go b.authenticateClient(conn)
	}
}

func (b *liveBridge) authenticateClient(conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			_ = conn.Close()
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	challengeRaw := make([]byte, 24)
	if _, err := rand.Read(challengeRaw); err != nil {
		_ = conn.Close()
		return
	}
	challenge := hex.EncodeToString(challengeRaw)
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(liveHandshake{Type: "challenge", Challenge: challenge, Protocol: liveProtocolLabel}); err != nil {
		_ = conn.Close()
		return
	}

	reader := bufio.NewReaderSize(conn, 4096)
	line, err := reader.ReadSlice('\n')
	if err != nil || len(line) > 4096 {
		_ = conn.Close()
		return
	}
	var response liveHandshake
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		_ = conn.Close()
		return
	}
	expected := liveProof(b.secret, challenge)
	if response.Type != "auth" || !hmac.Equal([]byte(strings.ToLower(response.Proof)), []byte(expected)) {
		_ = encoder.Encode(liveHandshake{Type: "error", Protocol: liveProtocolLabel})
		_ = conn.Close()
		return
	}
	if err := encoder.Encode(liveHandshake{Type: "ready", Protocol: liveProtocolLabel}); err != nil {
		_ = conn.Close()
		return
	}
	_ = conn.SetDeadline(time.Time{})

	client := &liveClient{conn: conn}
	b.clientsM.Lock()
	b.clients[client] = struct{}{}
	b.clientsM.Unlock()
	if status, err := b.fetchStatus(); err == nil {
		b.writeClient(client, liveEnvelope{Type: "status", Data: status})
	}

	_, _ = io.Copy(io.Discard, reader)
	b.removeClient(client)
}

func (b *liveBridge) removeClient(client *liveClient) {
	b.clientsM.Lock()
	if _, ok := b.clients[client]; ok {
		delete(b.clients, client)
		_ = client.conn.Close()
	}
	b.clientsM.Unlock()
}

func (b *liveBridge) writeClient(client *liveClient, value any) bool {
	client.mu.Lock()
	defer client.mu.Unlock()
	_ = client.conn.SetWriteDeadline(time.Now().Add(750 * time.Millisecond))
	err := json.NewEncoder(client.conn).Encode(value)
	_ = client.conn.SetWriteDeadline(time.Time{})
	if err != nil {
		b.removeClient(client)
		return false
	}
	return true
}

func (b *liveBridge) broadcast(value any) {
	b.clientsM.Lock()
	clients := make([]*liveClient, 0, len(b.clients))
	for client := range b.clients {
		clients = append(clients, client)
	}
	b.clientsM.Unlock()
	for _, client := range clients {
		b.writeClient(client, value)
	}
}

func (b *liveBridge) broadcastLoop() {
	ticker := time.NewTicker(livePollInterval)
	defer ticker.Stop()
	for range ticker.C {
		status, err := b.fetchStatus()
		if err != nil {
			continue
		}
		encoded, err := json.Marshal(status)
		if err != nil {
			continue
		}
		hash := sha256.Sum256(encoded)
		now := time.Now()
		changed := hash != b.lastHash
		heartbeatDue := now.Sub(b.lastSend) >= liveHeartbeatInterval
		if !changed && !heartbeatDue {
			continue
		}
		b.lastHash = hash
		b.lastSend = now
		b.broadcast(liveEnvelope{Type: "status", Data: status})
	}
}

func (b *liveBridge) fetchStatus() (map[string]any, error) {
	path := "/status"
	timestamp := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	nonceRaw := make([]byte, 20)
	if _, err := rand.Read(nonceRaw); err != nil {
		return nil, err
	}
	nonce := hex.EncodeToString(nonceRaw)
	emptyHashRaw := sha256.Sum256(nil)
	bodyHash := hex.EncodeToString(emptyHashRaw[:])
	mac := hmac.New(sha256.New, b.secret)
	_, _ = mac.Write([]byte(canonicalAPIMessage(http.MethodGet, path, timestamp, nonce, bodyHash)))
	signature := hex.EncodeToString(mac.Sum(nil))

	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:8787"+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-SmartCar-Timestamp", timestamp)
	req.Header.Set("X-SmartCar-Nonce", nonce)
	req.Header.Set("X-SmartCar-Content-SHA256", bodyHash)
	req.Header.Set("X-SmartCar-Signature", signature)
	req.Header.Set("Cache-Control", "no-store")
	client := &http.Client{Timeout: 650 * time.Millisecond}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status source HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	var status map[string]any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&status); err != nil {
		return nil, err
	}
	return status, nil
}
