package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mcpsoc/mcpsoc/pkg/mcp"
)

// ThreatIntelServer 威胁情报MCP服务器
type ThreatIntelServer struct {
	capabilities *mcp.ServerCapabilities
	tools        []mcp.Tool
	resources    []mcp.Resource
	indicators   []ThreatIndicator
	feeds        []ThreatFeed
}

// ThreatIndicator 威胁指标
type ThreatIndicator struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`        // ip, domain, hash, url, email
	Value       string    `json:"value"`
	Confidence  float64   `json:"confidence"`
	ThreatTypes []string  `json:"threat_types"`
	Source      string    `json:"source"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Description string    `json:"description"`
	Tags        []string  `json:"tags"`
}

// ThreatFeed 威胁情报源
type ThreatFeed struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Type        string    `json:"type"`        // stix, taxii, csv, json
	URL         string    `json:"url"`
	Format      string    `json:"format"`
	LastUpdate  time.Time `json:"last_update"`
	IsActive    bool      `json:"is_active"`
	Credentials map[string]string `json:"credentials"`
}

// IOCMatch IOC匹配结果
type IOCMatch struct {
	Indicator   ThreatIndicator `json:"indicator"`
	MatchType   string         `json:"match_type"`
	Confidence  float64        `json:"confidence"`
	Context     map[string]interface{} `json:"context"`
}

// NewThreatIntelServer 创建威胁情报服务器
func NewThreatIntelServer() *ThreatIntelServer {
	server := &ThreatIntelServer{
		capabilities: &mcp.ServerCapabilities{
			Tools: &mcp.ToolsCapability{
				ListChanged: false,
			},
			Resources: &mcp.ResourcesCapability{
				Subscribe:   false,
				ListChanged: false,
			},
		},
		indicators: []ThreatIndicator{},
		feeds:      []ThreatFeed{},
	}

	server.initializeTools()
	server.initializeResources()
	server.loadSampleIndicators()

	return server
}

// initializeTools 初始化工具
func (s *ThreatIntelServer) initializeTools() {
	s.tools = []mcp.Tool{
		{
			Name:        "lookup_ioc",
			Description: "查找IOC威胁指标",
			InputSchema: mcp.JSONSchema{
				Type: "object",
				Properties: map[string]mcp.JSONSchema{
					"ioc_value": {
						Type:        "string",
						Description: "IOC值 (IP地址、域名、哈希值等)",
					},
					"ioc_type": {
						Type:        "string",
						Description: "IOC类型 (ip, domain, hash, url, email)",
						Enum:        []interface{}{"ip", "domain", "hash", "url", "email"},
					},
				},
				Required: []string{"ioc_value"},
			},
		},
		{
			Name:        "bulk_ioc_check",
			Description: "批量检查IOC列表",
			InputSchema: mcp.JSONSchema{
				Type: "object",
				Properties: map[string]mcp.JSONSchema{
					"ioc_list": {
						Type:        "array",
						Description: "IOC列表",
						Items: &mcp.JSONSchema{
							Type: "object",
							Properties: map[string]mcp.JSONSchema{
								"value": {Type: "string"},
								"type":  {Type: "string"},
							},
						},
					},
				},
				Required: []string{"ioc_list"},
			},
		},
		{
			Name:        "add_threat_indicator",
			Description: "添加威胁指标",
			InputSchema: mcp.JSONSchema{
				Type: "object",
				Properties: map[string]mcp.JSONSchema{
					"type": {
						Type:        "string",
						Description: "指标类型",
						Enum:        []interface{}{"ip", "domain", "hash", "url", "email"},
					},
					"value": {
						Type:        "string",
						Description: "指标值",
					},
					"confidence": {
						Type:        "number",
						Description: "置信度 (0.0-1.0)",
					},
					"threat_types": {
						Type:        "array",
						Description: "威胁类型",
						Items:       &mcp.JSONSchema{Type: "string"},
					},
					"description": {
						Type:        "string",
						Description: "描述",
					},
					"source": {
						Type:        "string",
						Description: "来源",
					},
				},
				Required: []string{"type", "value"},
			},
		},
		{
			Name:        "search_indicators",
			Description: "搜索威胁指标",
			InputSchema: mcp.JSONSchema{
				Type: "object",
				Properties: map[string]mcp.JSONSchema{
					"query": {
						Type:        "string",
						Description: "搜索关键词",
					},
					"indicator_type": {
						Type:        "string",
						Description: "指标类型过滤",
					},
					"threat_type": {
						Type:        "string",
						Description: "威胁类型过滤",
					},
					"min_confidence": {
						Type:        "number",
						Description: "最小置信度",
					},
					"limit": {
						Type:        "integer",
						Description: "返回结果数量限制",
					},
				},
			},
		},
		{
			Name:        "update_threat_feeds",
			Description: "更新威胁情报源",
			InputSchema: mcp.JSONSchema{
				Type: "object",
				Properties: map[string]mcp.JSONSchema{
					"feed_id": {
						Type:        "string",
						Description: "情报源ID (可选，不指定则更新所有)",
					},
					"force": {
						Type:        "boolean",
						Description: "强制更新",
					},
				},
			},
		},
		{
			Name:        "get_ioc_context",
			Description: "获取IOC上下文信息",
			InputSchema: mcp.JSONSchema{
				Type: "object",
				Properties: map[string]mcp.JSONSchema{
					"ioc_value": {
						Type:        "string",
						Description: "IOC值",
					},
					"include_related": {
						Type:        "boolean",
						Description: "包含关联指标",
					},
					"include_campaigns": {
						Type:        "boolean",
						Description: "包含关联活动",
					},
				},
				Required: []string{"ioc_value"},
			},
		},
	}
}

// initializeResources 初始化资源
func (s *ThreatIntelServer) initializeResources() {
	s.resources = []mcp.Resource{
		{
			URI:         "threat-intel://indicators/all",
			Name:        "所有威胁指标",
			Description: "系统中的所有威胁指标列表",
			MimeType:    "application/json",
		},
		{
			URI:         "threat-intel://feeds/status",
			Name:        "情报源状态",
			Description: "威胁情报源的更新状态",
			MimeType:    "application/json",
		},
		{
			URI:         "threat-intel://statistics/summary",
			Name:        "威胁情报统计",
			Description: "威胁情报的统计摘要",
			MimeType:    "application/json",
		},
		{
			URI:         "threat-intel://export/stix",
			Name:        "STIX格式导出",
			Description: "以STIX格式导出威胁指标",
			MimeType:    "application/json",
		},
	}
}

// loadSampleIndicators 加载示例威胁指标
func (s *ThreatIntelServer) loadSampleIndicators() {
	sampleIndicators := []ThreatIndicator{
		{
			ID:          "ioc-001",
			Type:        "ip",
			Value:       "192.168.1.100",
			Confidence:  0.9,
			ThreatTypes: []string{"malware", "c2"},
			Source:      "internal_analysis",
			FirstSeen:   time.Now().Add(-24 * time.Hour),
			LastSeen:    time.Now().Add(-1 * time.Hour),
			Description: "已知的C2服务器IP地址",
			Tags:        []string{"high_priority", "c2_server"},
		},
		{
			ID:          "ioc-002",
			Type:        "domain",
			Value:       "evil.example.com",
			Confidence:  0.85,
			ThreatTypes: []string{"phishing", "malware"},
			Source:      "external_feed",
			FirstSeen:   time.Now().Add(-48 * time.Hour),
			LastSeen:    time.Now().Add(-6 * time.Hour),
			Description: "钓鱼网站域名",
			Tags:        []string{"phishing", "active"},
		},
		{
			ID:          "ioc-003",
			Type:        "hash",
			Value:       "d41d8cd98f00b204e9800998ecf8427e",
			Confidence:  0.95,
			ThreatTypes: []string{"malware", "trojan"},
			Source:      "malware_analysis",
			FirstSeen:   time.Now().Add(-72 * time.Hour),
			LastSeen:    time.Now().Add(-12 * time.Hour),
			Description: "恶意软件MD5哈希",
			Tags:        []string{"malware", "trojan", "confirmed"},
		},
	}

	s.indicators = append(s.indicators, sampleIndicators...)

	// 加载示例情报源
	sampleFeeds := []ThreatFeed{
		{
			ID:         "feed-001",
			Name:       "内部威胁情报",
			Type:       "json",
			URL:        "http://internal.company.com/threat-intel",
			Format:     "custom_json",
			LastUpdate: time.Now().Add(-2 * time.Hour),
			IsActive:   true,
		},
		{
			ID:         "feed-002",
			Name:       "开源威胁情报",
			Type:       "stix",
			URL:        "https://example.com/stix/feed",
			Format:     "stix2.1",
			LastUpdate: time.Now().Add(-4 * time.Hour),
			IsActive:   true,
		},
	}

	s.feeds = append(s.feeds, sampleFeeds...)
}

// handleMCPRequest 处理MCP请求
func (s *ThreatIntelServer) handleMCPRequest(c *gin.Context) {
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
func (s *ThreatIntelServer) handleInitialize(msg *mcp.JSONRPCMessage) *mcp.JSONRPCMessage {
	result := mcp.InitializeResult{
		ProtocolVersion: mcp.ProtocolVersion,
		Capabilities:    *s.capabilities,
		ServerInfo: mcp.ServerInfo{
			Name:    "Threat Intelligence MCP Server",
			Version: "1.0.0",
		},
	}

	return mcp.NewResponse(msg.ID, result)
}

// handleListTools 处理工具列表请求
func (s *ThreatIntelServer) handleListTools(msg *mcp.JSONRPCMessage) *mcp.JSONRPCMessage {
	result := mcp.ListToolsResult{
		Tools: s.tools,
	}

	return mcp.NewResponse(msg.ID, result)
}

// handleCallTool 处理工具调用请求
func (s *ThreatIntelServer) handleCallTool(msg *mcp.JSONRPCMessage) *mcp.JSONRPCMessage {
	var req mcp.CallToolRequest
	if err := json.Unmarshal(msg.Params.([]byte), &req); err != nil {
		return mcp.NewErrorResponse(msg.ID, mcp.ErrorCodeInvalidParams, "Invalid parameters", nil)
	}

	switch req.Name {
	case "lookup_ioc":
		return s.handleLookupIOC(msg.ID, req.Arguments)
	case "bulk_ioc_check":
		return s.handleBulkIOCCheck(msg.ID, req.Arguments)
	case "add_threat_indicator":
		return s.handleAddThreatIndicator(msg.ID, req.Arguments)
	case "search_indicators":
		return s.handleSearchIndicators(msg.ID, req.Arguments)
	case "update_threat_feeds":
		return s.handleUpdateThreatFeeds(msg.ID, req.Arguments)
	case "get_ioc_context":
		return s.handleGetIOCContext(msg.ID, req.Arguments)
	default:
		return mcp.NewErrorResponse(msg.ID, mcp.ErrorCodeMethodNotFound, "Tool not found", nil)
	}
}

func main() {
	// 创建威胁情报服务器
	server := NewThreatIntelServer()

	// 设置Gin路由
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	// 健康检查
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"server":  "Threat Intelligence MCP Server",
			"version": "1.0.0",
			"time":    time.Now().UTC(),
		})
	})

	// MCP endpoint
	router.POST("/mcp", server.handleMCPRequest)

	// 启动服务器
	srv := &http.Server{
		Addr:    ":8083",
		Handler: router,
	}

	go func() {
		log.Printf("威胁情报MCP服务器启动在端口 8083")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("服务器启动失败: %v", err)
		}
	}()

	// 优雅关闭
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("正在关闭威胁情报服务器...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("服务器强制关闭:", err)
	}

	log.Println("威胁情报服务器已退出")
}