package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// openAIProvider OpenAI提供商实现
type openAIProvider struct {
	name       string
	config     ProviderConfig
	logger     *logrus.Logger
	httpClient *http.Client
}

// NewOpenAIProvider 创建OpenAI提供商
func NewOpenAIProvider(config ProviderConfig, logger *logrus.Logger) (Provider, error) {
	if config.APIKey == "" {
		return nil, fmt.Errorf("OpenAI API key is required")
	}

	if config.Model == "" {
		config.Model = "gpt-3.5-turbo"
	}

	if config.BaseURL == "" {
		config.BaseURL = "https://api.openai.com/v1"
	}

	return &openAIProvider{
		name:       config.Name,
		config:     config,
		logger:     logger,
		httpClient: &http.Client{Timeout: 60 * time.Second},
	}, nil
}

// GetName 获取提供商名称
func (p *openAIProvider) GetName() string {
	return p.name
}

// GetType 获取提供商类型
func (p *openAIProvider) GetType() ProviderType {
	return ProviderOpenAI
}

// IsAvailable 检查服务是否可用
func (p *openAIProvider) IsAvailable(ctx context.Context) bool {
	// 发送简单的模型列表请求来检查API可用性
	req, err := http.NewRequestWithContext(ctx, "GET", p.config.BaseURL+"/models", nil)
	if err != nil {
		return false
	}
	
	req.Header.Set("Authorization", "Bearer "+p.config.APIKey)
	
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	return resp.StatusCode == http.StatusOK
}

// Query 执行AI查询
func (p *openAIProvider) Query(ctx context.Context, req *QueryRequest) (*QueryResponse, error) {
	startTime := time.Now()
	
	// 构建OpenAI API请求
	chatReq := p.buildChatCompletionRequest(req)
	
	// 发送请求
	chatResp, err := p.sendChatCompletionRequest(ctx, chatReq)
	if err != nil {
		return nil, err
	}
	
	// 构建响应
	response := &QueryResponse{
		ID:        fmt.Sprintf("openai-%d", time.Now().Unix()),
		Type:      req.Type,
		Query:     req.Query,
		Response:  chatResp.Choices[0].Message.Content,
		Confidence: 0.8, // OpenAI不提供置信度，使用默认值
		Tokens: TokenUsage{
			Prompt:     chatResp.Usage.PromptTokens,
			Completion: chatResp.Usage.CompletionTokens,
			Total:      chatResp.Usage.TotalTokens,
		},
		Duration:  time.Since(startTime),
		Context:   req.Context,
		CreatedAt: time.Now(),
	}
	
	return response, nil
}

// AnalyzeThreat 威胁分析
func (p *openAIProvider) AnalyzeThreat(ctx context.Context, data map[string]interface{}) (*ThreatAnalysisResult, error) {
	// 构建威胁分析提示
	prompt := p.buildThreatAnalysisPrompt(data)
	
	req := &QueryRequest{
		Type:        QueryTypeThreatAnalysis,
		Query:       prompt,
		Context:     data,
		MaxTokens:   1500,
		Temperature: 0.3, // 较低的温度以获得更一致的结果
	}
	
	resp, err := p.Query(ctx, req)
	if err != nil {
		return nil, err
	}
	
	// 解析威胁分析结果
	return p.parseThreatAnalysisResponse(resp.Response)
}

// GenerateIncidentResponse 生成事件响应
func (p *openAIProvider) GenerateIncidentResponse(ctx context.Context, incident map[string]interface{}) (*IncidentResponse, error) {
	// 构建事件响应提示
	prompt := p.buildIncidentResponsePrompt(incident)
	
	req := &QueryRequest{
		Type:        QueryTypeIncidentResponse,
		Query:       prompt,
		Context:     incident,
		MaxTokens:   2000,
		Temperature: 0.4,
	}
	
	resp, err := p.Query(ctx, req)
	if err != nil {
		return nil, err
	}
	
	// 解析事件响应结果
	return p.parseIncidentResponse(resp.Response)
}

// Close 关闭提供商连接
func (p *openAIProvider) Close() error {
	// OpenAI HTTP客户端无需特殊清理
	return nil
}

// OpenAI API数据结构
type chatCompletionRequest struct {
	Model       string                 `json:"model"`
	Messages    []chatMessage          `json:"messages"`
	MaxTokens   int                    `json:"max_tokens,omitempty"`
	Temperature float32                `json:"temperature,omitempty"`
	Stream      bool                   `json:"stream"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatCompletionResponse struct {
	ID      string   `json:"id"`
	Object  string   `json:"object"`
	Created int64    `json:"created"`
	Model   string   `json:"model"`
	Choices []choice `json:"choices"`
	Usage   usage    `json:"usage"`
}

type choice struct {
	Index        int         `json:"index"`
	Message      chatMessage `json:"message"`
	FinishReason string      `json:"finish_reason"`
}

type usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// buildChatCompletionRequest 构建聊天完成请求
func (p *openAIProvider) buildChatCompletionRequest(req *QueryRequest) *chatCompletionRequest {
	systemPrompt := p.getSystemPrompt(req.Type)
	
	messages := []chatMessage{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: req.Query},
	}
	
	maxTokens := req.MaxTokens
	if maxTokens == 0 {
		maxTokens = 2048
	}
	
	temperature := req.Temperature
	if temperature == 0 {
		temperature = 0.7
	}
	
	return &chatCompletionRequest{
		Model:       p.config.Model,
		Messages:    messages,
		MaxTokens:   maxTokens,
		Temperature: temperature,
		Stream:      false,
	}
}

// getSystemPrompt 获取系统提示
func (p *openAIProvider) getSystemPrompt(queryType QueryType) string {
	switch queryType {
	case QueryTypeThreatAnalysis:
		return `你是一个专业的网络安全威胁分析专家。请分析提供的安全数据，识别潜在威胁，评估风险级别，并提供具体的缓解建议。
请以JSON格式返回分析结果，包含threat_level(low/medium/high/critical)、confidence(0.0-1.0)、indicators、mitigations和actions字段。`
	case QueryTypeIncidentResponse:
		return `你是一个经验丰富的网络安全事件响应专家。请为给定的安全事件生成详细的响应计划，包括应急处理步骤、时间线和责任分配。
请提供结构化的响应，包含摘要、严重性评估、具体步骤和时间线。`
	case QueryTypeLogAnalysis:
		return `你是一个日志分析专家，擅长从安全日志中识别异常模式和潜在威胁。请分析提供的日志数据，识别可疑活动并提供详细解释。`
	default:
		return `你是一个专业的网络安全分析师，擅长分析各种安全相关的查询。请提供准确、详细且可操作的安全建议。使用专业术语，但保持回答的清晰易懂。`
	}
}

// sendChatCompletionRequest 发送聊天完成请求
func (p *openAIProvider) sendChatCompletionRequest(ctx context.Context, req *chatCompletionRequest) (*chatCompletionResponse, error) {
	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	
	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.config.BaseURL+"/chat/completions", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.config.APIKey)
	
	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OpenAI API returned status %d", resp.StatusCode)
	}
	
	var chatResp chatCompletionResponse
	if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	
	if len(chatResp.Choices) == 0 {
		return nil, fmt.Errorf("no choices returned from OpenAI")
	}
	
	return &chatResp, nil
}

// buildThreatAnalysisPrompt 构建威胁分析提示
func (p *openAIProvider) buildThreatAnalysisPrompt(data map[string]interface{}) string {
	var prompt strings.Builder
	
	prompt.WriteString("请分析以下安全数据并识别潜在威胁：\n\n")
	
	// 添加数据到提示中
	for key, value := range data {
		prompt.WriteString(fmt.Sprintf("%s: %v\n", key, value))
	}
	
	prompt.WriteString("\n请提供详细的威胁分析，包括：")
	prompt.WriteString("\n1. 威胁级别评估 (low/medium/high/critical)")
	prompt.WriteString("\n2. 置信度 (0.0-1.0)")
	prompt.WriteString("\n3. 威胁指标 (IOCs)")
	prompt.WriteString("\n4. 缓解措施")
	prompt.WriteString("\n5. 推荐行动")
	
	return prompt.String()
}

// buildIncidentResponsePrompt 构建事件响应提示
func (p *openAIProvider) buildIncidentResponsePrompt(incident map[string]interface{}) string {
	var prompt strings.Builder
	
	prompt.WriteString("请为以下安全事件生成详细的响应计划：\n\n")
	
	// 添加事件数据到提示中
	for key, value := range incident {
		prompt.WriteString(fmt.Sprintf("%s: %v\n", key, value))
	}
	
	prompt.WriteString("\n请提供结构化的事件响应计划，包括：")
	prompt.WriteString("\n1. 事件摘要和严重性评估")
	prompt.WriteString("\n2. immediate containment steps")
	prompt.WriteString("\n3. 详细调查步骤")
	prompt.WriteString("\n4. 恢复和监控措施")
	prompt.WriteString("\n5. 事件时间线")
	
	return prompt.String()
}

// parseThreatAnalysisResponse 解析威胁分析响应
func (p *openAIProvider) parseThreatAnalysisResponse(response string) (*ThreatAnalysisResult, error) {
	// 简单的响应解析 - 在实际项目中可能需要更复杂的JSON解析
	result := &ThreatAnalysisResult{
		ThreatLevel: "medium",
		Confidence:  0.7,
		Indicators:  []ThreatIndicator{},
		Mitigations: []string{},
		Actions:     []RecommendedAction{},
		Context:     map[string]interface{}{"raw_response": response},
	}
	
	// 尝试从响应中提取威胁级别
	response = strings.ToLower(response)
	if strings.Contains(response, "critical") || strings.Contains(response, "严重") {
		result.ThreatLevel = "critical"
		result.Confidence = 0.9
	} else if strings.Contains(response, "high") || strings.Contains(response, "高危") {
		result.ThreatLevel = "high"
		result.Confidence = 0.8
	} else if strings.Contains(response, "low") || strings.Contains(response, "低级") {
		result.ThreatLevel = "low"
		result.Confidence = 0.6
	}
	
	return result, nil
}

// parseIncidentResponse 解析事件响应
func (p *openAIProvider) parseIncidentResponse(response string) (*IncidentResponse, error) {
	// 简单的响应解析
	incident := &IncidentResponse{
		IncidentID: fmt.Sprintf("incident-%d", time.Now().Unix()),
		Summary:    "AI generated incident response",
		Severity:   "medium",
		Steps:      []ResponseStep{},
		Timeline:   []TimelineEvent{},
		Context:    map[string]interface{}{"raw_response": response},
	}
	
	// 基础步骤解析
	steps := []ResponseStep{
		{Order: 1, Action: "immediate_containment", Description: "立即隔离受影响的系统", Duration: "15分钟", Owner: "SOC团队"},
		{Order: 2, Action: "evidence_collection", Description: "收集和保存证据", Duration: "30分钟", Owner: "安全分析师"},
		{Order: 3, Action: "detailed_analysis", Description: "详细分析攻击向量", Duration: "2小时", Owner: "威胁分析师"},
		{Order: 4, Action: "remediation", Description: "实施修复措施", Duration: "1天", Owner: "系统管理员"},
	}
	
	incident.Steps = steps
	
	return incident, nil
}