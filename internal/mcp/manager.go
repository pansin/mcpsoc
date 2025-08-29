package mcp

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/mcpsoc/mcpsoc/pkg/mcp"
	"github.com/sirupsen/logrus"
)

// Manager MCP连接管理器
type Manager struct {
	logger      *logrus.Logger
	clients     map[string]*Client
	clientsMux  sync.RWMutex
	healthCheck *time.Ticker
	ctx         context.Context
	cancel      context.CancelFunc
}

// NewManager 创建新的MCP管理器
func NewManager(logger *logrus.Logger) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	
	m := &Manager{
		logger:      logger,
		clients:     make(map[string]*Client),
		healthCheck: time.NewTicker(30 * time.Second),
		ctx:         ctx,
		cancel:      cancel,
	}

	// 启动健康检查
	go m.runHealthCheck()

	return m
}

// AddServer 添加MCP服务器
func (m *Manager) AddServer(config ServerConfig) error {
	m.clientsMux.Lock()
	defer m.clientsMux.Unlock()

	if _, exists := m.clients[config.ID]; exists {
		return fmt.Errorf("server %s already exists", config.ID)
	}

	client, err := NewClient(config, m.logger)
	if err != nil {
		return fmt.Errorf("failed to create client for server %s: %w", config.ID, err)
	}

	// 连接到服务器
	if err := client.Connect(m.ctx); err != nil {
		return fmt.Errorf("failed to connect to server %s: %w", config.ID, err)
	}

	m.clients[config.ID] = client
	m.logger.WithField("server_id", config.ID).Info("MCP server added successfully")

	return nil
}

// RemoveServer 移除MCP服务器
func (m *Manager) RemoveServer(serverID string) error {
	m.clientsMux.Lock()
	defer m.clientsMux.Unlock()

	client, exists := m.clients[serverID]
	if !exists {
		return fmt.Errorf("server %s not found", serverID)
	}

	// 断开连接
	client.Disconnect()
	delete(m.clients, serverID)

	m.logger.WithField("server_id", serverID).Info("MCP server removed successfully")
	return nil
}

// GetServer 获取MCP服务器客户端
func (m *Manager) GetServer(serverID string) (*Client, error) {
	m.clientsMux.RLock()
	defer m.clientsMux.RUnlock()

	client, exists := m.clients[serverID]
	if !exists {
		return nil, fmt.Errorf("server %s not found", serverID)
	}

	return client, nil
}

// ListServers 列出所有MCP服务器
func (m *Manager) ListServers() []ServerStatus {
	m.clientsMux.RLock()
	defer m.clientsMux.RUnlock()

	servers := make([]ServerStatus, 0, len(m.clients))
	for id, client := range m.clients {
		servers = append(servers, ServerStatus{
			ID:           id,
			Name:         client.config.Name,
			Type:         client.config.Type,
			Status:       client.GetStatus(),
			Capabilities: client.GetCapabilities(),
			LastSeen:     client.GetLastSeen(),
		})
	}

	return servers
}

// CallTool 调用MCP工具
func (m *Manager) CallTool(serverID, toolName string, arguments map[string]interface{}) (*mcp.ToolResult, error) {
	client, err := m.GetServer(serverID)
	if err != nil {
		return nil, err
	}

	return client.CallTool(m.ctx, toolName, arguments)
}

// ListTools 列出服务器的所有工具
func (m *Manager) ListTools(serverID string) ([]mcp.Tool, error) {
	client, err := m.GetServer(serverID)
	if err != nil {
		return nil, err
	}

	return client.ListTools(m.ctx)
}

// ReadResource 读取资源
func (m *Manager) ReadResource(serverID, uri string) (*mcp.ResourceContent, error) {
	client, err := m.GetServer(serverID)
	if err != nil {
		return nil, err
	}

	return client.ReadResource(m.ctx, uri)
}

// ListResources 列出服务器的所有资源
func (m *Manager) ListResources(serverID string) ([]mcp.Resource, error) {
	client, err := m.GetServer(serverID)
	if err != nil {
		return nil, err
	}

	return client.ListResources(m.ctx)
}

// Close 关闭管理器
func (m *Manager) Close() {
	m.cancel()
	m.healthCheck.Stop()

	m.clientsMux.Lock()
	defer m.clientsMux.Unlock()

	for id, client := range m.clients {
		client.Disconnect()
		m.logger.WithField("server_id", id).Info("MCP server disconnected")
	}

	m.clients = make(map[string]*Client)
}

// runHealthCheck 运行健康检查
func (m *Manager) runHealthCheck() {
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-m.healthCheck.C:
			m.performHealthCheck()
		}
	}
}

// performHealthCheck 执行健康检查
func (m *Manager) performHealthCheck() {
	m.clientsMux.RLock()
	clients := make([]*Client, 0, len(m.clients))
	for _, client := range m.clients {
		clients = append(clients, client)
	}
	m.clientsMux.RUnlock()

	for _, client := range clients {
		go func(c *Client) {
			if err := c.Ping(m.ctx); err != nil {
				m.logger.WithFields(logrus.Fields{
					"server_id": c.config.ID,
					"error":     err,
				}).Warn("MCP server health check failed")
			}
		}(client)
	}
}

// ServerConfig MCP服务器配置
type ServerConfig struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	Transport   string            `json:"transport"`
	Endpoint    string            `json:"endpoint"`
	Credentials map[string]string `json:"credentials"`
	Enabled     bool              `json:"enabled"`
}

// ServerStatus MCP服务器状态
type ServerStatus struct {
	ID           string                  `json:"id"`
	Name         string                  `json:"name"`
	Type         string                  `json:"type"`
	Status       ClientStatus            `json:"status"`
	Capabilities *mcp.ServerCapabilities `json:"capabilities"`
	LastSeen     time.Time               `json:"last_seen"`
}

// ClientStatus 客户端状态
type ClientStatus string

const (
	StatusDisconnected ClientStatus = "disconnected"
	StatusConnecting   ClientStatus = "connecting"
	StatusConnected    ClientStatus = "connected"
	StatusError        ClientStatus = "error"
)