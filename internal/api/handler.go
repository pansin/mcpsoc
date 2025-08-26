package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mcpsoc/mcpsoc/internal/ai"
	"github.com/mcpsoc/mcpsoc/internal/mcp"
	"github.com/mcpsoc/mcpsoc/internal/storage"
	"github.com/mcpsoc/mcpsoc/pkg/mcp"
	"github.com/sirupsen/logrus"
)

// Handler API处理器
type Handler struct {
	logger        *logrus.Logger
	db            storage.Database
	mcpManager    *mcp.Manager
	aiService     ai.Service
	queryParser   *ai.QueryParser
	toolTranslator *ai.ToolTranslator
}

// NewHandler 创建新的API处理器
func NewHandler(logger *logrus.Logger, db storage.Database, mcpManager *mcp.Manager, aiService ai.Service) *Handler {
	queryParser := ai.NewQueryParser(aiService, logger)
	toolTranslator := ai.NewToolTranslator(mcpManager, logger)
	
	return &Handler{
		logger:        logger,
		db:           db,
		mcpManager:   mcpManager,
		aiService:    aiService,
		queryParser:  queryParser,
		toolTranslator: toolTranslator,
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

	if req.Query == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "query cannot be empty"})
		return
	}

	startTime := time.Now()
	queryID := generateQueryID()

	h.logger.WithFields(logrus.Fields{
		"query_id": queryID,
		"query":    req.Query,
		"session":  req.SessionID,
	}).Info("Processing natural language query")

	// 获取可用的MCP工具
	availableTools, err := h.getAvailableTools()
	if err != nil {
		h.logger.WithError(err).Error("Failed to get available tools")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get available tools"})
		return
	}

	// 使用查询解析器解析自然语言
	ctx := context.Background()
	parsedQuery, err := h.queryParser.ParseQuery(ctx, req.Query, availableTools)
	if err != nil {
		h.logger.WithError(err).Error("Failed to parse query")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse query"})
		return
	}

	// 执行解析后的查询
	execResult, err := h.toolTranslator.ExecuteQuery(ctx, parsedQuery)
	if err != nil {
		h.logger.WithError(err).Error("Failed to execute query")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to execute query"})
		return
	}

	// 构建响应
	response := NaturalQueryResponse{
		QueryID:       queryID,
		Status:        "completed",
		Result:        execResult,
		Insights:      h.convertToInsights(execResult),
		Actions:       h.convertToActions(execResult.Recommendations),
		Evidence:      h.convertToEvidence(execResult.Results),
		ExecutionTime: time.Since(startTime).Seconds(),
	}

	// 记录查询历史
	history := &storage.QueryHistory{
		QueryType:     "natural",
		QueryText:     req.Query,
		ResultCount:   len(execResult.Results),
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

// generateMockResponse 生成模拟响应
func (h *Handler) generateMockResponse(queryID, query string, startTime time.Time) NaturalQueryResponse {
	return NaturalQueryResponse{
		QueryID: queryID,
		Status:  "completed",
		Result: map[string]interface{}{
			"summary": "发现15个来自可疑IP的连接",
			"data": []map[string]interface{}{
				{
					"timestamp":    time.Now().Add(-1 * time.Hour),
					"src_ip":       "192.168.1.100",
					"dst_ip":       "10.0.0.5",
					"dst_port":     22,
					"protocol":     "tcp",
					"action":       "blocked",
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
}

// buildNaturalQueryResponse 构建自然语言查询响应
func (h *Handler) buildNaturalQueryResponse(queryID, originalQuery string, aiResponse *ai.QueryResponse, startTime time.Time) NaturalQueryResponse {
	return NaturalQueryResponse{
		QueryID: queryID,
		Status:  "completed",
		Result: map[string]interface{}{
			"ai_response": aiResponse.Response,
			"query_type": string(aiResponse.Type),
			"confidence": aiResponse.Confidence,
			"tokens":     aiResponse.Tokens,
			"summary":    h.extractSummaryFromAIResponse(aiResponse.Response),
		},
		Insights: []Insight{
			{
				Type:       "ai_analysis",
				Severity:   h.inferSeverityFromResponse(aiResponse.Response),
				Message:    "AI分析结果",
				Confidence: aiResponse.Confidence,
			},
		},
		Actions:       []RecommendedAction{}, // 将由威胁分析填充
		Evidence: []Evidence{
			{
				Source:    "ai_service",
				Type:      "analysis_result",
				Data:      aiResponse,
				Timestamp: aiResponse.CreatedAt,
			},
		},
		ExecutionTime: time.Since(startTime).Seconds(),
	}
}

// extractSummaryFromAIResponse 从AI响应中提取摘要
func (h *Handler) extractSummaryFromAIResponse(response string) string {
	// 简单的摘要提取逻辑
	if len(response) > 200 {
		return response[:200] + "..."
	}
	return response
}

// inferSeverityFromResponse 从响应中推断严重程度
func (h *Handler) inferSeverityFromResponse(response string) string {
	response = strings.ToLower(response)
	if strings.Contains(response, "critical") || strings.Contains(response, "严重") {
		return "critical"
	} else if strings.Contains(response, "high") || strings.Contains(response, "高") {
		return "high"
	} else if strings.Contains(response, "low") || strings.Contains(response, "低") {
		return "low"
	}
	return "medium"
}

// getAvailableTools 获取可用的MCP工具
func (h *Handler) getAvailableTools() ([]ai.AvailableTool, error) {
	var tools []ai.AvailableTool
	
	// 获取所有MCP服务器
	servers := h.mcpManager.ListServers()
	
	for _, server := range servers {
		// 获取每个服务器的工具列表
		serverTools, err := h.mcpManager.ListTools(server.ID)
		if err != nil {
			h.logger.WithError(err).WithField("server_id", server.ID).Warn("Failed to get tools for server")
			continue
		}
		
		// 转换为AvailableTool格式
		for _, tool := range serverTools {
			availableTool := ai.AvailableTool{
				Name:        tool.Name,
				Description: tool.Description,
				Server:      server.ID,
				Parameters:  h.convertToolParameters(tool.InputSchema),
			}
			tools = append(tools, availableTool)
		}
	}
	
	return tools, nil
}

// convertToolParameters 转换工具参数格式
func (h *Handler) convertToolParameters(schema mcp.JSONSchema) []ai.ToolParameter {
	var parameters []ai.ToolParameter
	
	if schema.Properties != nil {
		for name, prop := range schema.Properties {
			param := ai.ToolParameter{
				Name:        name,
				Type:        prop.Type,
				Description: prop.Description,
				Required:    h.isRequiredParameter(name, schema.Required),
			}
			parameters = append(parameters, param)
		}
	}
	
	return parameters
}

// isRequiredParameter 检查参数是否必需
func (h *Handler) isRequiredParameter(paramName string, required []string) bool {
	for _, req := range required {
		if req == paramName {
			return true
		}
	}
	return false
}

// convertToInsights 转换执行结果为洞察
func (h *Handler) convertToInsights(execResult *ai.AggregatedResult) []Insight {
	var insights []Insight
	
	// 基于执行结果的成功率生成洞察
	if execResult.ErrorCount > 0 {
		insights = append(insights, Insight{
			Type:       "execution_warning",
			Severity:   "medium",
			Message:    fmt.Sprintf("有%d个工具调用失败，可能影响分析结果的完整性", execResult.ErrorCount),
			Confidence: 0.9,
		})
	}
	
	// 基于执行时间生成洞察
	if execResult.TotalDuration.Seconds() > 5 {
		insights = append(insights, Insight{
			Type:       "performance_warning",
			Severity:   "low",
			Message:    fmt.Sprintf("查询执行时间较长（%.2f秒），建议优化查询条件", execResult.TotalDuration.Seconds()),
			Confidence: 0.8,
		})
	}
	
	// 基于意图类型生成特定洞察
	switch execResult.Intent {
	case "threat_analysis":
		insights = append(insights, Insight{
			Type:       "threat_analysis",
			Severity:   "high",
			Message:    "完成了威胁分析，建议查看详细的威胁指标和缓解措施",
			Confidence: 0.85,
		})
	case "log_analysis":
		insights = append(insights, Insight{
			Type:       "log_analysis",
			Severity:   "medium",
			Message:    "日志分析完成，建议关注异常模式和时间趋势",
			Confidence: 0.8,
		})
	}
	
	return insights
}

// convertToActions 转换推荐列表为行动
func (h *Handler) convertToActions(recommendations []string) []RecommendedAction {
	var actions []RecommendedAction
	
	for i, rec := range recommendations {
		action := RecommendedAction{
			Action:   fmt.Sprintf("action_%d", i+1),
			Target:   "system",
			Reason:   rec,
			Priority: h.inferPriorityFromRecommendation(rec),
		}
		actions = append(actions, action)
	}
	
	return actions
}

// convertToEvidence 转换执行结果为证据
func (h *Handler) convertToEvidence(results []ai.ExecutionResult) []Evidence {
	var evidence []Evidence
	
	for _, result := range results {
		ev := Evidence{
			Source:    result.ToolCall.Server,
			Type:      "tool_execution_result",
			Data: map[string]interface{}{
				"tool":     result.ToolCall.Tool,
				"success":  result.Success,
				"result":   result.Result,
				"duration": result.Duration.String(),
			},
			Timestamp: result.Timestamp,
		}
		evidence = append(evidence, ev)
	}
	
	return evidence
}

// inferPriorityFromRecommendation 从推荐内容推断优先级
func (h *Handler) inferPriorityFromRecommendation(recommendation string) string {
	recommendation = strings.ToLower(recommendation)
	
	if strings.Contains(recommendation, "紧急") || strings.Contains(recommendation, "立即") || 
	   strings.Contains(recommendation, "urgent") || strings.Contains(recommendation, "immediate") {
		return "high"
	}
	
	if strings.Contains(recommendation, "建议") || strings.Contains(recommendation, "考虑") ||
	   strings.Contains(recommendation, "recommend") || strings.Contains(recommendation, "consider") {
		return "low"
	}
	
	return "medium"
}