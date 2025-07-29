package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/mcpsoc/mcpsoc/pkg/mcp"
)

// Transport MCP传输接口
type Transport interface {
	Connect(ctx context.Context) error
	Send(msg *mcp.JSONRPCMessage) error
	Receive() (*mcp.JSONRPCMessage, error)
	Close() error
}

// NewTransport 创建新的传输实例
func NewTransport(transportType, endpoint string, credentials map[string]string) (Transport, error) {
	switch transportType {
	case "stdio":
		return NewStdioTransport(endpoint, credentials)
	case "http":
		return NewHTTPTransport(endpoint, credentials)
	case "websocket":
		return NewWebSocketTransport(endpoint, credentials)
	case "tcp":
		return NewTCPTransport(endpoint, credentials)
	default:
		return nil, fmt.Errorf("unsupported transport type: %s", transportType)
	}
}

// StdioTransport 标准输入输出传输
type StdioTransport struct {
	command string
	args    []string
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	stdout  io.ReadCloser
	scanner *bufio.Scanner
	encoder *json.Encoder
	mu      sync.Mutex
}

// NewStdioTransport 创建标准输入输出传输
func NewStdioTransport(command string, credentials map[string]string) (*StdioTransport, error) {
	return &StdioTransport{
		command: command,
	}, nil
}

// Connect 连接
func (t *StdioTransport) Connect(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.cmd = exec.CommandContext(ctx, t.command, t.args...)
	
	stdin, err := t.cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdin pipe: %w", err)
	}
	t.stdin = stdin

	stdout, err := t.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	t.stdout = stdout

	if err := t.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start command: %w", err)
	}

	t.scanner = bufio.NewScanner(t.stdout)
	t.encoder = json.NewEncoder(t.stdin)

	return nil
}

// Send 发送消息
func (t *StdioTransport) Send(msg *mcp.JSONRPCMessage) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.encoder.Encode(msg)
}

// Receive 接收消息
func (t *StdioTransport) Receive() (*mcp.JSONRPCMessage, error) {
	if !t.scanner.Scan() {
		if err := t.scanner.Err(); err != nil {
			return nil, err
		}
		return nil, io.EOF
	}

	return mcp.UnmarshalMessage(t.scanner.Bytes())
}

// Close 关闭连接
func (t *StdioTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.stdin != nil {
		t.stdin.Close()
	}
	if t.stdout != nil {
		t.stdout.Close()
	}
	if t.cmd != nil && t.cmd.Process != nil {
		t.cmd.Process.Kill()
		t.cmd.Wait()
	}

	return nil
}

// HTTPTransport HTTP传输
type HTTPTransport struct {
	endpoint string
	client   *http.Client
	headers  map[string]string
	msgChan  chan *mcp.JSONRPCMessage
	mu       sync.Mutex
}

// NewHTTPTransport 创建HTTP传输
func NewHTTPTransport(endpoint string, credentials map[string]string) (*HTTPTransport, error) {
	headers := make(map[string]string)
	if apiKey, ok := credentials["api_key"]; ok {
		headers["Authorization"] = "Bearer " + apiKey
	}

	return &HTTPTransport{
		endpoint: endpoint,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		headers: headers,
		msgChan: make(chan *mcp.JSONRPCMessage, 100),
	}, nil
}

// Connect 连接
func (t *HTTPTransport) Connect(ctx context.Context) error {
	// HTTP传输不需要持久连接
	return nil
}

// Send 发送消息
func (t *HTTPTransport) Send(msg *mcp.JSONRPCMessage) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	data, err := msg.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	req, err := http.NewRequest("POST", t.endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	for key, value := range t.headers {
		req.Header.Set(key, value)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP error: %d", resp.StatusCode)
	}

	// 如果是请求消息，读取响应
	if msg.IsRequest() {
		var respMsg mcp.JSONRPCMessage
		if err := json.NewDecoder(resp.Body).Decode(&respMsg); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}

		select {
		case t.msgChan <- &respMsg:
		default:
			return fmt.Errorf("message channel full")
		}
	}

	return nil
}

// Receive 接收消息
func (t *HTTPTransport) Receive() (*mcp.JSONRPCMessage, error) {
	select {
	case msg := <-t.msgChan:
		return msg, nil
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("receive timeout")
	}
}

// Close 关闭连接
func (t *HTTPTransport) Close() error {
	close(t.msgChan)
	return nil
}

// WebSocketTransport WebSocket传输
type WebSocketTransport struct {
	endpoint string
	headers  http.Header
	conn     *websocket.Conn
	mu       sync.Mutex
}

// NewWebSocketTransport 创建WebSocket传输
func NewWebSocketTransport(endpoint string, credentials map[string]string) (*WebSocketTransport, error) {
	headers := make(http.Header)
	if apiKey, ok := credentials["api_key"]; ok {
		headers.Set("Authorization", "Bearer "+apiKey)
	}

	return &WebSocketTransport{
		endpoint: endpoint,
		headers:  headers,
	}, nil
}

// Connect 连接
func (t *WebSocketTransport) Connect(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	conn, _, err := dialer.DialContext(ctx, t.endpoint, t.headers)
	if err != nil {
		return fmt.Errorf("failed to connect websocket: %w", err)
	}

	t.conn = conn
	return nil
}

// Send 发送消息
func (t *WebSocketTransport) Send(msg *mcp.JSONRPCMessage) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.conn.WriteJSON(msg)
}

// Receive 接收消息
func (t *WebSocketTransport) Receive() (*mcp.JSONRPCMessage, error) {
	var msg mcp.JSONRPCMessage
	err := t.conn.ReadJSON(&msg)
	if err != nil {
		return nil, err
	}
	return &msg, nil
}

// Close 关闭连接
func (t *WebSocketTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.conn != nil {
		return t.conn.Close()
	}
	return nil
}

// TCPTransport TCP传输
type TCPTransport struct {
	endpoint string
	conn     net.Conn
	encoder  *json.Encoder
	decoder  *json.Decoder
	mu       sync.Mutex
}

// NewTCPTransport 创建TCP传输
func NewTCPTransport(endpoint string, credentials map[string]string) (*TCPTransport, error) {
	return &TCPTransport{
		endpoint: endpoint,
	}, nil
}

// Connect 连接
func (t *TCPTransport) Connect(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	conn, err := net.DialTimeout("tcp", t.endpoint, 10*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect TCP: %w", err)
	}

	t.conn = conn
	t.encoder = json.NewEncoder(conn)
	t.decoder = json.NewDecoder(conn)

	return nil
}

// Send 发送消息
func (t *TCPTransport) Send(msg *mcp.JSONRPCMessage) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.encoder.Encode(msg)
}

// Receive 接收消息
func (t *TCPTransport) Receive() (*mcp.JSONRPCMessage, error) {
	var msg mcp.JSONRPCMessage
	err := t.decoder.Decode(&msg)
	if err != nil {
		return nil, err
	}
	return &msg, nil
}

// Close 关闭连接
func (t *TCPTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.conn != nil {
		return t.conn.Close()
	}
	return nil
}