package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mcpsoc/mcpsoc/internal/mcp"
	"github.com/mcpsoc/mcpsoc/internal/storage"
	"github.com/sirupsen/logrus"
)

// Handler API处理器
type Handler struct {
	logger     *logrus.Logger
	db         storage.Database
	mcpManager *mcp.Manager
}

// NewHandler 创建新的API处理器
func NewHandler(logger *logrus.Logger, db storage.Database, mcpManager *mcp.Manager) *Handler {
	return &Handler{
		logger:     logger,
		db:         db,
		mcpManager: mcpManager,
	}
}

// NaturalQueryRequest 自然语言查询请求
type NaturalQueryRequest struct {
	Query     string                 `json:"query" binding:"required"`
	Context   map[string]interface{} `json:"context"`
	SessionID string                 `json:"session_id"`
}

// NaturalQueryResponse 自然语言查询响应
type NaturalQueryResponse struct {
	QueryID       string                 `json:"query_id"`
	Status        string                 `json:"status"`
	Result        interface{}            `json:"result"`
	Insights      []Insight              `json:"insights"`
	Actions       []RecommendedAction    `json:"actions"`
	Evidence      []Evidence             `json:"evidence"`
	ExecutionTime float64                `json:"execution_time"`
}

// Insight 洞察信息
type Insight struct {
	Type       string  `json:"type"`
	Severity   string  `json:"severity"`
	Message    string  `json:"message"`
	Confidence float64 `json:"confidence"`
}

// RecommendedAction 推荐行动
type RecommendedAction struct {
	Action   string `json:"action"`
	Target   string `json:"target"`
	Reason   string `json:"reason"`
	Priority string `json:"priority"`
}

// Evidence 证据信息
type Evidence struct {
	Source    string      `json:"source"`
	Type      string      `json:"type"`
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
}

// HandleNaturalQuery 处理自然语言查询
func (h *Handler) HandleNaturalQuery(c *gin.Context) {
	var req NaturalQueryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	startTime := time.Now()
	queryID := generateQueryID()

	h.logger.WithFields(logrus.Fields{
		"query_id": queryID,
		"query":    req.Query,
		"context":  req.Context,
	}).Info("Processing natural language query")

	// 这里应该实现实际的自然语言处理逻辑
	// 目前返回模拟数据
	response := NaturalQueryResponse{
		QueryID: queryID,
		Status:  "completed",
		Result: map[string]interface{}{
			"summary": "发现15个来自可疑IP的连接",
			"data": []map[string]interface{}{
				{
					"timestamp": time.Now().Add(-1 * time.Hour),
					"src_ip":    "192.168.1.100",
					"dst_ip":    "10.0.0.5",
					"dst_port":  22,
					"protocol":  "tcp",
					"action":    "blocked",
					"threat_level": "high",
				},
			},
		},
		Insights: []Insight{
			{
				Type:       "threat_indicator",
				Severity:   "high",
				Message:    "检测到来自已知恶意IP 192.168.1.100的多次连接尝试",
				Confidence: 0.95,
			},
		},
		Actions: []RecommendedAction{
			{
				Action:   "block_ip",
				Target:   "192.168.1.100",
				Reason:   "多次恶意连接尝试",
				Priority: "high",
			},
		},
		Evidence: []Evidence{
			{
				Source:    "firewall",
				Type:      "log_entry",
				Data:      map[string]interface{}{"blocked_connections": 15},
				Timestamp: time.Now(),
			},
		},
		ExecutionTime: time.Since(startTime).Seconds(),
	}

	// 记录查询历史
	history := &storage.QueryHistory{
		QueryType:     "natural",
		QueryText:     req.Query,
		ResultCount:   1,
		ExecutionTime: int64(time.Since(startTime).Milliseconds()),
		Status:        "success",
	}
	
	repo := storage.NewQueryHistoryRepository(h.db.GetDB())
	if err := repo.Create(history); err != nil {
		h.logger.WithError(err).Error("Failed to save query history")
	}

	c.JSON(http.StatusOK, response)
}

// StructuredQueryRequest 结构化查询请求
type StructuredQueryRequest struct {
	DataSource   string                 `json:"data_source" binding:"required"`
	Filters      map[string]interface{} `json:"filters"`
	Aggregation  map[string]interface{} `json:"aggregation"`
	Limit        int                    `json:"limit"`
	Offset       int                    `json:"offset"`
}

// StructuredQueryResponse 结构化查询响应
type StructuredQueryResponse struct {
	TotalCount    int64                  `json:"total_count"`
	Aggregations  map[string]interface{} `json:"aggregations"`
	Data          []interface{}          `json:"data"`
	ExecutionTime float64                `json:"execution_time"`
}

// HandleStructuredQuery 处理结构化查询
func (h *Handler) HandleStructuredQuery(c *gin.Context) {
	var req StructuredQueryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	startTime := time.Now()

	h.logger.WithFields(logrus.Fields{
		"data_source": req.DataSource,
		"filters":     req.Filters,
	}).Info("Processing structured query")

	// 根据数据源查询数据
	var data []interface{}
	var totalCount int64

	switch req.DataSource {
	case "security_events":
		repo := storage.NewSecurityEventRepository(h.db.GetDB())
		events, err := repo.List(req.Limit, req.Offset, req.Filters)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		
		count, err := repo.Count(req.Filters)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		for _, event := range events {
			data = append(data, event)
		}
		totalCount = count

	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported data source"})
		return
	}

	response := StructuredQueryResponse{
		TotalCount:    totalCount,
		Data:          data,
		ExecutionTime: time.Since(startTime).Seconds(),
	}

	c.JSON(http.StatusOK, response)
}

// ListMCPServers 列出MCP服务器
func (h *Handler) ListMCPServers(c *gin.Context) {
	servers := h.mcpManager.ListServers()
	
	response := map[string]interface{}{
		"servers": servers,
		"total":   len(servers),
		"healthy": countHealthyServers(servers),
		"unhealthy": len(servers) - countHealthyServers(servers),
	}

	c.JSON(http.StatusOK, response)
}

// GetMCPServer 获取MCP服务器详情
func (h *Handler) GetMCPServer(c *gin.Context) {
	serverID := c.Param("id")
	
	client, err := h.mcpManager.GetServer(serverID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "server not found"})
		return
	}

	// 获取服务器工具列表
	tools, err := h.mcpManager.ListTools(serverID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to list tools")
		tools = []mcp.Tool{}
	}

	// 获取服务器资源列表
	resources, err := h.mcpManager.ListResources(serverID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to list resources")
		resources = []mcp.Resource{}
	}

	response := map[string]interface{}{
		"id":           serverID,
		"name":         client.GetCapabilities(),
		"status":       client.GetStatus(),
		"capabilities": client.GetCapabilities(),
		"tools":        tools,
		"resources":    resources,
		"last_seen":    client.GetLastSeen(),
	}

	c.JSON(http.StatusOK, response)
}

// CallMCPToolRequest 调用MCP工具请求
type CallMCPToolRequest struct {
	Arguments map[string]interface{} `json:"arguments"`
}

// CallMCPTool 调用MCP工具
func (h *Handler) CallMCPTool(c *gin.Context) {
	serverID := c.Param("id")
	toolName := c.Param("tool")

	var req CallMCPToolRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.logger.WithFields(logrus.Fields{
		"server_id": serverID,
		"tool_name": toolName,
		"arguments": req.Arguments,
	}).Info("Calling MCP tool")

	result, err := h.mcpManager.CallTool(serverID, toolName, req.Arguments)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	response := map[string]interface{}{
		"execution_id": generateExecutionID(),
		"status":       "success",
		"result":       result,
		"execution_time": 0.5, // 模拟执行时间
	}

	c.JSON(http.StatusOK, response)
}

// 辅助函数

func generateQueryID() string {
	return "query-" + strconv.FormatInt(time.Now().UnixNano(), 36)
}

func generateExecutionID() string {
	return "exec-" + strconv.FormatInt(time.Now().UnixNano(), 36)
}

func countHealthyServers(servers []mcp.ServerStatus) int {
	count := 0
	for _, server := range servers {
		if server.Status == mcp.StatusConnected {
			count++
		}
	}
	return count
}