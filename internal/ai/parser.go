package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// QueryParser 查询解析器
type QueryParser struct {
	aiService     Service
	promptManager *PromptManager
	logger        *logrus.Logger
}

// NewQueryParser 创建新的查询解析器
func NewQueryParser(aiService Service, logger *logrus.Logger) *QueryParser {
	return &QueryParser{
		aiService:     aiService,
		promptManager: NewPromptManager(),
		logger:        logger,
	}
}

// ParsedQuery 解析后的查询
type ParsedQuery struct {
	Intent         string                   `json:"intent"`
	Confidence     float64                  `json:"confidence"`
	ToolCalls      []ToolCall              `json:"tool_calls"`
	ExecutionPlan  ExecutionPlan           `json:"execution_plan"`
	ExpectedResult string                   `json:"expected_result"`
	Parameters     map[string]interface{}   `json:"parameters"`
	TimeRange      *TimeRange              `json:"time_range,omitempty"`
	Filters        map[string]interface{}   `json:"filters,omitempty"`
}

// ToolCall MCP工具调用
type ToolCall struct {
	Tool      string                 `json:"tool"`
	Arguments map[string]interface{} `json:"arguments"`
	Reason    string                 `json:"reason"`
	Server    string                 `json:"server,omitempty"`
}

// ExecutionPlan 执行计划
type ExecutionPlan struct {
	Parallel   []string   `json:"parallel"`
	Sequential [][]string `json:"sequential"`
}

// TimeRange 时间范围
type TimeRange struct {
	Start  time.Time `json:"start"`
	End    time.Time `json:"end"`
	Period string    `json:"period"` // 1h, 24h, 7d, etc.
}

// AvailableTool 可用工具信息
type AvailableTool struct {
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Server      string              `json:"server"`
	Parameters  []ToolParameter     `json:"parameters"`
}

// ToolParameter 工具参数
type ToolParameter struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
}

// ParseQuery 解析自然语言查询
func (qp *QueryParser) ParseQuery(ctx context.Context, query string, availableTools []AvailableTool) (*ParsedQuery, error) {
	qp.logger.WithField("query", query).Info("Parsing natural language query")

	// 预处理查询
	normalizedQuery := qp.normalizeQuery(query)
	
	// 提取基础信息
	timeRange := qp.extractTimeRange(normalizedQuery)
	intent := qp.classifyIntent(normalizedQuery)
	
	// 使用AI进行高级解析
	aiParsedQuery, err := qp.parseWithAI(ctx, normalizedQuery, availableTools)
	if err != nil {
		qp.logger.WithError(err).Warn("AI parsing failed, falling back to rule-based parsing")
		return qp.parseWithRules(normalizedQuery, availableTools, timeRange, intent)
	}
	
	// 合并结果
	if aiParsedQuery.TimeRange == nil && timeRange != nil {
		aiParsedQuery.TimeRange = timeRange
	}
	
	if aiParsedQuery.Intent == "" {
		aiParsedQuery.Intent = intent
	}
	
	return aiParsedQuery, nil
}

// normalizeQuery 规范化查询
func (qp *QueryParser) normalizeQuery(query string) string {
	// 转换为小写
	normalized := strings.ToLower(strings.TrimSpace(query))
	
	// 标准化时间表达式
	timePatterns := map[string]string{
		"最近一小时":   "1h",
		"过去一小时":   "1h", 
		"最近24小时":  "24h",
		"过去24小时":  "24h",
		"最近一天":    "24h",
		"过去一天":    "24h",
		"最近一周":    "7d",
		"过去一周":    "7d",
		"最近七天":    "7d",
		"过去七天":    "7d",
		"最近30天":   "30d",
		"过去30天":   "30d",
		"最近一个月":   "30d",
		"过去一个月":   "30d",
	}
	
	for pattern, replacement := range timePatterns {
		normalized = strings.ReplaceAll(normalized, pattern, replacement)
	}
	
	return normalized
}

// extractTimeRange 提取时间范围
func (qp *QueryParser) extractTimeRange(query string) *TimeRange {
	patterns := []struct {
		regex  *regexp.Regexp
		period string
	}{
		{regexp.MustCompile(`(\d+)h`), ""},
		{regexp.MustCompile(`(\d+)d`), ""},
		{regexp.MustCompile(`(\d+)天`), "d"},
		{regexp.MustCompile(`(\d+)小时`), "h"},
		{regexp.MustCompile(`(\d+)分钟`), "m"},
	}
	
	now := time.Now()
	
	for _, pattern := range patterns {
		if matches := pattern.regex.FindStringSubmatch(query); len(matches) > 1 {
			duration := matches[1]
			unit := pattern.period
			if unit == "" {
				// 从正则表达式中提取单位
				if strings.Contains(matches[0], "h") {
					unit = "h"
				} else if strings.Contains(matches[0], "d") {
					unit = "d"
				} else if strings.Contains(matches[0], "m") {
					unit = "m"
				}
			}
			
			var d time.Duration
			switch unit {
			case "m":
				d = time.Duration(parseIntOrDefault(duration, 60)) * time.Minute
			case "h":
				d = time.Duration(parseIntOrDefault(duration, 1)) * time.Hour
			case "d":
				d = time.Duration(parseIntOrDefault(duration, 1)) * 24 * time.Hour
			default:
				continue
			}
			
			return &TimeRange{
				Start:  now.Add(-d),
				End:    now,
				Period: duration + unit,
			}
		}
	}
	
	return nil
}

// classifyIntent 分类查询意图
func (qp *QueryParser) classifyIntent(query string) string {
	intentPatterns := map[string][]string{
		"threat_analysis": {
			"威胁", "threat", "攻击", "attack", "恶意", "malicious", 
			"入侵", "intrusion", "可疑", "suspicious",
		},
		"incident_response": {
			"事件", "incident", "响应", "response", "处置", "handle",
			"应急", "emergency",
		},
		"log_analysis": {
			"日志", "log", "分析", "analysis", "查看", "view",
			"搜索", "search",
		},
		"vulnerability_assessment": {
			"漏洞", "vulnerability", "cve", "安全漏洞", "security flaw",
			"弱点", "weakness",
		},
		"monitoring": {
			"监控", "monitor", "实时", "realtime", "状态", "status",
			"健康", "health",
		},
		"forensics": {
			"取证", "forensics", "调查", "investigate", "追踪", "trace",
			"证据", "evidence",
		},
	}
	
	query = strings.ToLower(query)
	
	for intent, keywords := range intentPatterns {
		for _, keyword := range keywords {
			if strings.Contains(query, keyword) {
				return intent
			}
		}
	}
	
	return "general"
}

// parseWithAI 使用AI解析查询
func (qp *QueryParser) parseWithAI(ctx context.Context, query string, availableTools []AvailableTool) (*ParsedQuery, error) {
	// 构建提示词数据
	data := map[string]interface{}{
		"UserQuery":      query,
		"AvailableTools": availableTools,
	}
	
	// 渲染提示词
	prompt, err := qp.promptManager.RenderPrompt("nl_to_mcp_query", data)
	if err != nil {
		return nil, fmt.Errorf("failed to render prompt: %w", err)
	}
	
	// 调用AI服务
	req := &QueryRequest{
		Type:        QueryTypeNaturalLanguage,
		Query:       prompt,
		Context:     data,
		MaxTokens:   1500,
		Temperature: 0.3,
	}
	
	resp, err := qp.aiService.Query(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("AI query failed: %w", err)
	}
	
	// 解析AI响应
	return qp.parseAIResponse(resp.Response)
}

// parseAIResponse 解析AI响应
func (qp *QueryParser) parseAIResponse(response string) (*ParsedQuery, error) {
	// 尝试提取JSON部分
	jsonStart := strings.Index(response, "{")
	jsonEnd := strings.LastIndex(response, "}")
	
	if jsonStart == -1 || jsonEnd == -1 {
		return nil, fmt.Errorf("no valid JSON found in AI response")
	}
	
	jsonStr := response[jsonStart : jsonEnd+1]
	
	var parsed ParsedQuery
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %w", err)
	}
	
	return &parsed, nil
}

// parseWithRules 基于规则的解析（备用方案）
func (qp *QueryParser) parseWithRules(query string, availableTools []AvailableTool, timeRange *TimeRange, intent string) (*ParsedQuery, error) {
	qp.logger.Info("Using rule-based parsing as fallback")
	
	parsed := &ParsedQuery{
		Intent:     intent,
		Confidence: 0.6, // 规则解析的置信度相对较低
		ToolCalls:  []ToolCall{},
		TimeRange:  timeRange,
		Parameters: make(map[string]interface{}),
		Filters:    make(map[string]interface{}),
	}
	
	// 基于查询内容推荐工具调用
	query = strings.ToLower(query)
	
	// 防火墙相关查询
	if strings.Contains(query, "防火墙") || strings.Contains(query, "firewall") ||
		strings.Contains(query, "阻止") || strings.Contains(query, "block") {
		
		for _, tool := range availableTools {
			if strings.Contains(tool.Server, "firewall") {
				parsed.ToolCalls = append(parsed.ToolCalls, ToolCall{
					Tool:   "get_firewall_logs",
					Server: tool.Server,
					Arguments: map[string]interface{}{
						"time_range": "1h",
						"limit":      100,
					},
					Reason: "查询防火墙日志以分析安全事件",
				})
				break
			}
		}
	}
	
	// WAF相关查询
	if strings.Contains(query, "waf") || strings.Contains(query, "web攻击") ||
		strings.Contains(query, "sql注入") || strings.Contains(query, "xss") {
		
		for _, tool := range availableTools {
			if strings.Contains(tool.Server, "waf") {
				parsed.ToolCalls = append(parsed.ToolCalls, ToolCall{
					Tool:   "get_attack_logs",
					Server: tool.Server,
					Arguments: map[string]interface{}{
						"time_range": "24h",
						"severity":   "high",
					},
					Reason: "查询WAF攻击日志",
				})
				break
			}
		}
	}
	
	// 威胁情报查询
	if strings.Contains(query, "威胁情报") || strings.Contains(query, "threat intel") ||
		strings.Contains(query, "ioc") || strings.Contains(query, "指标") {
		
		for _, tool := range availableTools {
			if strings.Contains(tool.Server, "threat") {
				parsed.ToolCalls = append(parsed.ToolCalls, ToolCall{
					Tool:   "search_indicators",
					Server: tool.Server,
					Arguments: map[string]interface{}{
						"types": []string{"ip", "domain", "hash"},
						"limit": 50,
					},
					Reason: "搜索相关威胁指标",
				})
				break
			}
		}
	}
	
	// 设置执行计划
	if len(parsed.ToolCalls) > 0 {
		// 大多数查询可以并行执行
		parallel := make([]string, len(parsed.ToolCalls))
		for i, call := range parsed.ToolCalls {
			parallel[i] = call.Tool
		}
		parsed.ExecutionPlan = ExecutionPlan{
			Parallel:   parallel,
			Sequential: [][]string{},
		}
	}
	
	parsed.ExpectedResult = fmt.Sprintf("基于查询'%s'的安全分析结果", query)
	
	return parsed, nil
}

// parseIntOrDefault 解析整数或返回默认值
func parseIntOrDefault(s string, defaultValue int) int {
	if i := 0; len(s) > 0 {
		for _, c := range s {
			if c >= '0' && c <= '9' {
				i = i*10 + int(c-'0')
			} else {
				return defaultValue
			}
		}
		if i > 0 {
			return i
		}
	}
	return defaultValue
}

// ValidateToolCall 验证工具调用
func (qp *QueryParser) ValidateToolCall(toolCall ToolCall, availableTools []AvailableTool) error {
	// 查找对应的工具定义
	var toolDef *AvailableTool
	for _, tool := range availableTools {
		if tool.Name == toolCall.Tool {
			toolDef = &tool
			break
		}
	}
	
	if toolDef == nil {
		return fmt.Errorf("tool not found: %s", toolCall.Tool)
	}
	
	// 验证必需参数
	for _, param := range toolDef.Parameters {
		if param.Required {
			if _, exists := toolCall.Arguments[param.Name]; !exists {
				return fmt.Errorf("required parameter missing: %s", param.Name)
			}
		}
	}
	
	return nil
}

// GetSupportedIntents 获取支持的查询意图
func (qp *QueryParser) GetSupportedIntents() []string {
	return []string{
		"threat_analysis",
		"incident_response", 
		"log_analysis",
		"vulnerability_assessment",
		"monitoring",
		"forensics",
		"general",
	}
}