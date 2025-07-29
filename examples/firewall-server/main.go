package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mcpsoc/mcpsoc/pkg/mcp"
)

// FirewallServer 防火墙MCP服务器
type FirewallServer struct {
	capabilities *mcp.ServerCapabilities
	tools        []mcp.Tool
	resources    []mcp.Resource
}

// NewFirewallServer 创建新的防火墙服务器
func NewFirewallServer() *FirewallServer {
	server := &FirewallServer{
		capabilities: &mcp.ServerCapabilities{
			Tools: &mcp.ToolsCapability{
				ListChanged: false,
			},
			Resources: &mcp.ResourcesCapability{
				Subscribe:   false,
				ListChanged: false,
			},
		},
	}

	server.initializeTools()
	server.initializeResources()

	return server
}

// initializeTools 初始化工具
func (s *FirewallServer) initializeTools() {
	s.tools = []mcp.Tool{
		{
			Name:        "get_firewall_logs",
			Description: "获取防火墙日志",
			InputSchema: mcp.JSONSchema{
				Type: "object",
				Properties: map[string]mcp.JSONSchema{
					"time_range": {
						Type:        "string",
						Description: "时间范围 (1h, 24h, 7d)",
					},
					"filter": {
						Type:        "string",
						Description: "过滤条件",
					},
					"limit": {
						Type:        "integer",
						Description: "返回记录数限制",
					},
				},
			},
		},
		{
			Name:        "block_ip",
			Description: "阻止IP地址访问",
			InputSchema: mcp.JSONSchema{
				Type: "object",
				Properties: map[string]mcp.JSONSchema{
					"ip_address": {
						Type:        "string",
						Description: "要阻止的IP地址",
					},
					"duration": {
						Type:        "integer",
						Description: "阻止时长（秒）",
					},
					"reason": {
						Type:        "string",
						Description: "阻止原因",
					},
				},
				Required: []string{"ip_address"},
			},
		},
		{
			Name:        "unblock_ip",
			Description: "解除IP地址阻止",
			InputSchema: mcp.JSONSchema{
				Type: "object",
				Properties: map[string]mcp.JSONSchema{
					"ip_address": {
						Type:        "string",
						Description: "要解除阻止的IP地址",
					},
				},
				Required: []string{"ip_address"},
			},
		},
		{
			Name:        "get_blocked_ips",
			Description: "获取被阻止的IP列表",
			InputSchema: mcp.JSONSchema{
				Type: "object",
				Properties: map[string]mcp.JSONSchema{
					"active_only": {
						Type:        "boolean",
						Description: "只返回当前活跃的阻止规则",
					},
				},
			},
		},
		{
			Name:        "get_firewall_rules",
			Description: "获取防火墙规则",
			InputSchema: mcp.JSONSchema{
				Type: "object",
				Properties: map[string]mcp.JSONSchema{
					"interface": {
						Type:        "string",
						Description: "网络接口名称",
					},
					"rule_type": {
						Type:        "string",
						Description: "规则类型 (allow, block)",
					},
				},
			},
		},
	}
}

// initializeResources 初始化资源
func (s *FirewallServer) initializeResources() {
	s.resources = []mcp.Resource{
		{
			URI:         "firewall://logs/realtime",
			Name:        "实时防火墙日志",
			Description: "实时防火墙日志流",
			MimeType:    "application/json",
		},
		{
			URI:         "firewall://rules/current",
			Name:        "当前防火墙规则",
			Description: "当前生效的防火墙规则配置",
			MimeType:    "application/json",
		},
		{
			URI:         "firewall://stats/traffic",
			Name:        "流量统计",
			Description: "网络流量统计信息",
			MimeType:    "application/json",
		},
	}
}

// handleMCPRequest 处理MCP请求
func (s *FirewallServer) handleMCPRequest(c *gin.Context) {
	var msg mcp.JSONRPCMessage
	if err := c.ShouldBindJSON(&msg); err != nil {
		response := mcp.NewErrorResponse(nil, mcp.ErrorCodeInvalidRequest, "Invalid JSON-RPC request", nil)
		c.JSON(http.StatusBadRequest, response)
		return
	}

	var response *mcp.JSONRPCMessage

	switch msg.Method {
	case mcp.MethodInitialize:
		response = s.handleInitialize(&msg)
	case mcp.MethodListTools:
		response = s.handleListTools(&msg)
	case mcp.MethodCallTool:
		response = s.handleCallTool(&msg)
	case mcp.MethodListResources:
		response = s.handleListResources(&msg)
	case mcp.MethodReadResource:
		response = s.handleReadResource(&msg)
	case mcp.MethodPing:
		response = mcp.NewResponse(msg.ID, map[string]interface{}{"pong": true})
	default:
		response = mcp.NewErrorResponse(msg.ID, mcp.ErrorCodeMethodNotFound, "Method not found", nil)
	}

	c.JSON(http.StatusOK, response)
}

// handleInitialize 处理初始化请求
func (s *FirewallServer) handleInitialize(msg *mcp.JSONRPCMessage) *mcp.JSONRPCMessage {
	result := mcp.InitializeResult{
		ProtocolVersion: mcp.ProtocolVersion,
		Capabilities:    *s.capabilities,
		ServerInfo: mcp.ServerInfo{
			Name:    "pfSense Firewall MCP Server",
			Version: "1.0.0",
		},
	}

	return mcp.NewResponse(msg.ID, result)
}

// handleListTools 处理工具列表请求
func (s *FirewallServer) handleListTools(msg *mcp.JSONRPCMessage) *mcp.JSONRPCMessage {
	result := mcp.ListToolsResult{
		Tools: s.tools,
	}

	return mcp.NewResponse(msg.ID, result)
}

// handleCallTool 处理工具调用请求
func (s *FirewallServer) handleCallTool(msg *mcp.JSONRPCMessage) *mcp.JSONRPCMessage {
	var req mcp.CallToolRequest
	if err := json.Unmarshal(mustMarshal(msg.Params), &req); err != nil {
		return mcp.NewErrorResponse(msg.ID, mcp.ErrorCodeInvalidParams, "Invalid parameters", nil)
	}

	var result *mcp.ToolResult
	var err error

	switch req.Name {
	case "get_firewall_logs":
		result, err = s.getFirewallLogs(req.Arguments)
	case "block_ip":
		result, err = s.blockIP(req.Arguments)
	case "unblock_ip":
		result, err = s.unblockIP(req.Arguments)
	case "get_blocked_ips":
		result, err = s.getBlockedIPs(req.Arguments)
	case "get_firewall_rules":
		result, err = s.getFirewallRules(req.Arguments)
	default:
		return mcp.NewErrorResponse(msg.ID, mcp.ErrorCodeMethodNotFound, "Tool not found", nil)
	}

	if err != nil {
		return mcp.NewErrorResponse(msg.ID, mcp.ErrorCodeInternalError, err.Error(), nil)
	}

	return mcp.NewResponse(msg.ID, result)
}

// handleListResources 处理资源列表请求
func (s *FirewallServer) handleListResources(msg *mcp.JSONRPCMessage) *mcp.JSONRPCMessage {
	result := mcp.ListResourcesResult{
		Resources: s.resources,
	}

	return mcp.NewResponse(msg.ID, result)
}

// handleReadResource 处理读取资源请求
func (s *FirewallServer) handleReadResource(msg *mcp.JSONRPCMessage) *mcp.JSONRPCMessage {
	var req mcp.ReadResourceRequest
	if err := json.Unmarshal(mustMarshal(msg.Params), &req); err != nil {
		return mcp.NewErrorResponse(msg.ID, mcp.ErrorCodeInvalidParams, "Invalid parameters", nil)
	}

	var content *mcp.ResourceContent
	var err error

	switch req.URI {
	case "firewall://logs/realtime":
		content, err = s.getRealtimeLogs()
	case "firewall://rules/current":
		content, err = s.getCurrentRules()
	case "firewall://stats/traffic":
		content, err = s.getTrafficStats()
	default:
		return mcp.NewErrorResponse(msg.ID, mcp.ErrorCodeInvalidParams, "Resource not found", nil)
	}

	if err != nil {
		return mcp.NewErrorResponse(msg.ID, mcp.ErrorCodeInternalError, err.Error(), nil)
	}

	return mcp.NewResponse(msg.ID, content)
}

// 工具实现方法

func (s *FirewallServer) getFirewallLogs(args map[string]interface{}) (*mcp.ToolResult, error) {
	// 模拟防火墙日志数据
	logs := []map[string]interface{}{
		{
			"timestamp":  time.Now().Add(-1 * time.Hour).Format(time.RFC3339),
			"src_ip":     "192.168.1.100",
			"dst_ip":     "10.0.0.5",
			"src_port":   12345,
			"dst_port":   22,
			"protocol":   "tcp",
			"action":     "block",
			"interface":  "wan",
			"rule_id":    "block_ssh_external",
			"threat_level": "high",
		},
		{
			"timestamp":  time.Now().Add(-30 * time.Minute).Format(time.RFC3339),
			"src_ip":     "203.0.113.10",
			"dst_ip":     "10.0.0.1",
			"src_port":   54321,
			"dst_port":   80,
			"protocol":   "tcp",
			"action":     "allow",
			"interface":  "wan",
			"rule_id":    "allow_http",
			"threat_level": "low",
		},
	}

	return &mcp.ToolResult{
		Content: []mcp.Content{
			{
				Type: "text",
				Text: fmt.Sprintf("找到 %d 条防火墙日志记录", len(logs)),
			},
			{
				Type:     "application/json",
				Text:     mustMarshalString(logs),
				MimeType: "application/json",
			},
		},
	}, nil
}

func (s *FirewallServer) blockIP(args map[string]interface{}) (*mcp.ToolResult, error) {
	ipAddress, ok := args["ip_address"].(string)
	if !ok {
		return nil, fmt.Errorf("ip_address parameter is required")
	}

	duration := 3600 // 默认1小时
	if d, ok := args["duration"].(float64); ok {
		duration = int(d)
	}

	reason := "Manual block"
	if r, ok := args["reason"].(string); ok {
		reason = r
	}

	// 模拟阻止IP的操作
	result := map[string]interface{}{
		"blocked_ip":  ipAddress,
		"rule_id":     fmt.Sprintf("block_%s_%d", ipAddress, time.Now().Unix()),
		"expires_at":  time.Now().Add(time.Duration(duration) * time.Second).Format(time.RFC3339),
		"reason":      reason,
		"status":      "active",
	}

	return &mcp.ToolResult{
		Content: []mcp.Content{
			{
				Type: "text",
				Text: fmt.Sprintf("IP地址 %s 已成功阻止，持续时间 %d 秒", ipAddress, duration),
			},
			{
				Type:     "application/json",
				Text:     mustMarshalString(result),
				MimeType: "application/json",
			},
		},
	}, nil
}

func (s *FirewallServer) unblockIP(args map[string]interface{}) (*mcp.ToolResult, error) {
	ipAddress, ok := args["ip_address"].(string)
	if !ok {
		return nil, fmt.Errorf("ip_address parameter is required")
	}

	// 模拟解除阻止的操作
	result := map[string]interface{}{
		"unblocked_ip": ipAddress,
		"status":       "removed",
		"timestamp":    time.Now().Format(time.RFC3339),
	}

	return &mcp.ToolResult{
		Content: []mcp.Content{
			{
				Type: "text",
				Text: fmt.Sprintf("IP地址 %s 的阻止规则已成功移除", ipAddress),
			},
			{
				Type:     "application/json",
				Text:     mustMarshalString(result),
				MimeType: "application/json",
			},
		},
	}, nil
}

func (s *FirewallServer) getBlockedIPs(args map[string]interface{}) (*mcp.ToolResult, error) {
	// 模拟被阻止的IP列表
	blockedIPs := []map[string]interface{}{
		{
			"ip_address": "192.168.1.100",
			"rule_id":    "block_192.168.1.100_1640995200",
			"blocked_at": time.Now().Add(-2 * time.Hour).Format(time.RFC3339),
			"expires_at": time.Now().Add(1 * time.Hour).Format(time.RFC3339),
			"reason":     "Suspicious activity",
			"status":     "active",
		},
		{
			"ip_address": "203.0.113.50",
			"rule_id":    "block_203.0.113.50_1640991600",
			"blocked_at": time.Now().Add(-4 * time.Hour).Format(time.RFC3339),
			"expires_at": time.Now().Add(-1 * time.Hour).Format(time.RFC3339),
			"reason":     "Brute force attack",
			"status":     "expired",
		},
	}

	return &mcp.ToolResult{
		Content: []mcp.Content{
			{
				Type: "text",
				Text: fmt.Sprintf("找到 %d 个被阻止的IP地址", len(blockedIPs)),
			},
			{
				Type:     "application/json",
				Text:     mustMarshalString(blockedIPs),
				MimeType: "application/json",
			},
		},
	}, nil
}

func (s *FirewallServer) getFirewallRules(args map[string]interface{}) (*mcp.ToolResult, error) {
	// 模拟防火墙规则
	rules := []map[string]interface{}{
		{
			"rule_id":     "allow_http",
			"interface":   "wan",
			"action":      "allow",
			"protocol":    "tcp",
			"src_addr":    "any",
			"dst_addr":    "10.0.0.0/24",
			"dst_port":    "80",
			"description": "Allow HTTP traffic",
			"enabled":     true,
		},
		{
			"rule_id":     "allow_https",
			"interface":   "wan",
			"action":      "allow",
			"protocol":    "tcp",
			"src_addr":    "any",
			"dst_addr":    "10.0.0.0/24",
			"dst_port":    "443",
			"description": "Allow HTTPS traffic",
			"enabled":     true,
		},
		{
			"rule_id":     "block_ssh_external",
			"interface":   "wan",
			"action":      "block",
			"protocol":    "tcp",
			"src_addr":    "any",
			"dst_addr":    "10.0.0.0/24",
			"dst_port":    "22",
			"description": "Block external SSH access",
			"enabled":     true,
		},
	}

	return &mcp.ToolResult{
		Content: []mcp.Content{
			{
				Type: "text",
				Text: fmt.Sprintf("找到 %d 条防火墙规则", len(rules)),
			},
			{
				Type:     "application/json",
				Text:     mustMarshalString(rules),
				MimeType: "application/json",
			},
		},
	}, nil
}

// 资源实现方法

func (s *FirewallServer) getRealtimeLogs() (*mcp.ResourceContent, error) {
	logs := []map[string]interface{}{
		{
			"timestamp": time.Now().Format(time.RFC3339),
			"level":     "info",
			"message":   "Connection established from 192.168.1.10 to 10.0.0.5:80",
		},
		{
			"timestamp": time.Now().Add(-1 * time.Minute).Format(time.RFC3339),
			"level":     "warning",
			"message":   "Multiple failed login attempts from 203.0.113.100",
		},
	}

	return &mcp.ResourceContent{
		Contents: []mcp.Content{
			{
				Type:     "application/json",
				Text:     mustMarshalString(logs),
				MimeType: "application/json",
			},
		},
	}, nil
}

func (s *FirewallServer) getCurrentRules() (*mcp.ResourceContent, error) {
	rules := map[string]interface{}{
		"total_rules": 15,
		"active_rules": 12,
		"disabled_rules": 3,
		"last_modified": time.Now().Add(-1 * time.Hour).Format(time.RFC3339),
	}

	return &mcp.ResourceContent{
		Contents: []mcp.Content{
			{
				Type:     "application/json",
				Text:     mustMarshalString(rules),
				MimeType: "application/json",
			},
		},
	}, nil
}

func (s *FirewallServer) getTrafficStats() (*mcp.ResourceContent, error) {
	stats := map[string]interface{}{
		"bytes_in":     1024000,
		"bytes_out":    2048000,
		"packets_in":   1500,
		"packets_out":  2000,
		"connections":  45,
		"timestamp":    time.Now().Format(time.RFC3339),
	}

	return &mcp.ResourceContent{
		Contents: []mcp.Content{
			{
				Type:     "application/json",
				Text:     mustMarshalString(stats),
				MimeType: "application/json",
			},
		},
	}, nil
}

// 辅助函数

func mustMarshal(v interface{}) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}

func mustMarshalString(v interface{}) string {
	return string(mustMarshal(v))
}

func main() {
	// 创建防火墙服务器
	firewallServer := NewFirewallServer()

	// 设置Gin路由
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	// 健康检查
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"service": "firewall-mcp-server",
			"version": "1.0.0",
			"time":    time.Now().UTC(),
		})
	})

	// MCP端点
	router.POST("/mcp", firewallServer.handleMCPRequest)

	// 启动服务器
	srv := &http.Server{
		Addr:    ":8081",
		Handler: router,
	}

	go func() {
		log.Printf("Firewall MCP Server starting on port 8081")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// 等待中断信号
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}

	log.Println("Server exited")
}