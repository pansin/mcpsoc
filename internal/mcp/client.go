package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mcpsoc/mcpsoc/pkg/mcp"
	"github.com/sirupsen/logrus"
)

// Client MCP客户端
type Client struct {
	config       ServerConfig
	logger       *logrus.Logger
	transport    Transport
	status       int32 // atomic
	capabilities *mcp.ServerCapabilities
	lastSeen     time.Time
	requestID    int64 // atomic
	pendingReqs  map[interface{}]chan *mcp.JSONRPCMessage
	reqMux       sync.RWMutex
}

// NewClient 创建新的MCP客户端
func NewClient(config ServerConfig, logger *logrus.Logger) (*Client, error) {
	transport, err := NewTransport(config.Transport, config.Endpoint, config.Credentials)
	if err != nil {
		return nil, fmt.Errorf("failed to create transport: %w", err)
	}

	return &Client{
		config:      config,
		logger:      logger.WithField("server_id", config.ID),
		transport:   transport,
		status:      int32(StatusDisconnected),
		pendingReqs: make(map[interface{}]chan *mcp.JSONRPCMessage),
		lastSeen:    time.Now(),
	}, nil
}

// Connect 连接到MCP服务器
func (c *Client) Connect(ctx context.Context) error {
	atomic.StoreInt32(&c.status, int32(StatusConnecting))

	// 建立传输连接
	if err := c.transport.Connect(ctx); err != nil {
		atomic.StoreInt32(&c.status, int32(StatusError))
		return fmt.Errorf("transport connection failed: %w", err)
	}

	// 启动消息处理
	go c.handleMessages()

	// 发送初始化请求
	if err := c.initialize(ctx); err != nil {
		atomic.StoreInt32(&c.status, int32(StatusError))
		return fmt.Errorf("initialization failed: %w", err)
	}

	atomic.StoreInt32(&c.status, int32(StatusConnected))
	c.lastSeen = time.Now()

	c.logger.Info("MCP client connected successfully")
	return nil
}

// Disconnect 断开连接
func (c *Client) Disconnect() {
	atomic.StoreInt32(&c.status, int32(StatusDisconnected))
	c.transport.Close()
	c.logger.Info("MCP client disconnected")
}

// GetStatus 获取客户端状态
func (c *Client) GetStatus() ClientStatus {
	status := atomic.LoadInt32(&c.status)
	return ClientStatus(status)
}

// GetCapabilities 获取服务器能力
func (c *Client) GetCapabilities() *mcp.ServerCapabilities {
	return c.capabilities
}

// GetLastSeen 获取最后活跃时间
func (c *Client) GetLastSeen() time.Time {
	return c.lastSeen
}

// Ping 发送ping请求
func (c *Client) Ping(ctx context.Context) error {
	req := mcp.NewRequest(c.nextRequestID(), mcp.MethodPing, nil)
	_, err := c.sendRequest(ctx, req, 5*time.Second)
	if err == nil {
		c.lastSeen = time.Now()
	}
	return err
}

// ListTools 列出所有工具
func (c *Client) ListTools(ctx context.Context) ([]mcp.Tool, error) {
	req := mcp.NewRequest(c.nextRequestID(), mcp.MethodListTools, nil)
	resp, err := c.sendRequest(ctx, req, 10*time.Second)
	if err != nil {
		return nil, err
	}

	var result mcp.ListToolsResult
	if err := c.unmarshalResult(resp.Result, &result); err != nil {
		return nil, err
	}

	return result.Tools, nil
}

// CallTool 调用工具
func (c *Client) CallTool(ctx context.Context, name string, arguments map[string]interface{}) (*mcp.ToolResult, error) {
	params := mcp.CallToolRequest{
		Name:      name,
		Arguments: arguments,
	}

	req := mcp.NewRequest(c.nextRequestID(), mcp.MethodCallTool, params)
	resp, err := c.sendRequest(ctx, req, 30*time.Second)
	if err != nil {
		return nil, err
	}

	var result mcp.ToolResult
	if err := c.unmarshalResult(resp.Result, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// ListResources 列出所有资源
func (c *Client) ListResources(ctx context.Context) ([]mcp.Resource, error) {
	req := mcp.NewRequest(c.nextRequestID(), mcp.MethodListResources, nil)
	resp, err := c.sendRequest(ctx, req, 10*time.Second)
	if err != nil {
		return nil, err
	}

	var result mcp.ListResourcesResult
	if err := c.unmarshalResult(resp.Result, &result); err != nil {
		return nil, err
	}

	return result.Resources, nil
}

// ReadResource 读取资源
func (c *Client) ReadResource(ctx context.Context, uri string) (*mcp.ResourceContent, error) {
	params := mcp.ReadResourceRequest{
		URI: uri,
	}

	req := mcp.NewRequest(c.nextRequestID(), mcp.MethodReadResource, params)
	resp, err := c.sendRequest(ctx, req, 30*time.Second)
	if err != nil {
		return nil, err
	}

	var result mcp.ResourceContent
	if err := c.unmarshalResult(resp.Result, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// initialize 初始化连接
func (c *Client) initialize(ctx context.Context) error {
	params := mcp.InitializeRequest{
		ProtocolVersion: mcp.ProtocolVersion,
		Capabilities: mcp.ClientCapabilities{
			Experimental: make(map[string]interface{}),
		},
		ClientInfo: mcp.ClientInfo{
			Name:    "MCPSoc",
			Version: "1.0.0",
		},
	}

	req := mcp.NewRequest(c.nextRequestID(), mcp.MethodInitialize, params)
	resp, err := c.sendRequest(ctx, req, 10*time.Second)
	if err != nil {
		return err
	}

	var result mcp.InitializeResult
	if err := c.unmarshalResult(resp.Result, &result); err != nil {
		return err
	}

	c.capabilities = &result.Capabilities

	// 发送initialized通知
	notification := mcp.NewNotification(mcp.MethodInitialized, nil)
	return c.transport.Send(notification)
}

// sendRequest 发送请求并等待响应
func (c *Client) sendRequest(ctx context.Context, req *mcp.JSONRPCMessage, timeout time.Duration) (*mcp.JSONRPCMessage, error) {
	// 创建响应通道
	respChan := make(chan *mcp.JSONRPCMessage, 1)
	
	c.reqMux.Lock()
	c.pendingReqs[req.ID] = respChan
	c.reqMux.Unlock()

	// 清理函数
	defer func() {
		c.reqMux.Lock()
		delete(c.pendingReqs, req.ID)
		c.reqMux.Unlock()
		close(respChan)
	}()

	// 发送请求
	if err := c.transport.Send(req); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	// 等待响应
	select {
	case resp := <-respChan:
		if resp.IsError() {
			return nil, resp.Error
		}
		return resp, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("request timeout after %v", timeout)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// handleMessages 处理接收到的消息
func (c *Client) handleMessages() {
	for {
		msg, err := c.transport.Receive()
		if err != nil {
			c.logger.WithError(err).Error("Failed to receive message")
			break
		}

		if msg.IsResponse() {
			// 处理响应消息
			c.reqMux.RLock()
			respChan, exists := c.pendingReqs[msg.ID]
			c.reqMux.RUnlock()

			if exists {
				select {
				case respChan <- msg:
				default:
					c.logger.Warn("Response channel full, dropping message")
				}
			} else {
				c.logger.WithField("id", msg.ID).Warn("Received response for unknown request")
			}
		} else if msg.IsNotification() {
			// 处理通知消息
			c.handleNotification(msg)
		}
	}
}

// handleNotification 处理通知消息
func (c *Client) handleNotification(msg *mcp.JSONRPCMessage) {
	c.logger.WithFields(logrus.Fields{
		"method": msg.Method,
		"params": msg.Params,
	}).Debug("Received notification")

	// 这里可以处理各种通知，如工具列表变更等
}

// nextRequestID 生成下一个请求ID
func (c *Client) nextRequestID() int64 {
	return atomic.AddInt64(&c.requestID, 1)
}

// unmarshalResult 反序列化结果
func (c *Client) unmarshalResult(result interface{}, target interface{}) error {
	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("failed to unmarshal result: %w", err)
	}

	return nil
}