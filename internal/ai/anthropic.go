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

// anthropicProvider Anthropic提供商实现
type anthropicProvider struct {
	name       string
	config     ProviderConfig
	logger     *logrus.Logger
	httpClient *http.Client
}

// NewAnthropicProvider 创建Anthropic提供商
func NewAnthropicProvider(config ProviderConfig, logger *logrus.Logger) (Provider, error) {
	if config.APIKey == "" {
		return nil, fmt.Errorf("Anthropic API key is required")
	}

	if config.Model == "" {
		config.Model = "claude-3-haiku-20240307"
	}

	if config.BaseURL == "" {
		config.BaseURL = "https://api.anthropic.com/v1"
	}

	return &anthropicProvider{
		name:       config.Name,
		config:     config,
		logger:     logger,
		httpClient: &http.Client{Timeout: 60 * time.Second},
	}, nil
}

// GetName 获取提供商名称
func (p *anthropicProvider) GetName() string {
	return p.name
}

// GetType 获取提供商类型
func (p *anthropicProvider) GetType() ProviderType {
	return ProviderAnthropic
}

// IsAvailable 检查服务是否可用
func (p *anthropicProvider) IsAvailable(ctx context.Context) bool {
	// 发送简单的消息请求来检查API可用性
	testReq := &anthropicMessageRequest{
		Model:     p.config.Model,
		MaxTokens: 10,
		Messages: []anthropicMessage{
			{Role: "user", Content: "Hello"},
		},
	}
	
	_, err := p.sendMessageRequest(ctx, testReq)
	return err == nil
}

// Query 执行AI查询
func (p *anthropicProvider) Query(ctx context.Context, req *QueryRequest) (*QueryResponse, error) {
	startTime := time.Now()
	
	// 构建Anthropic API请求
	msgReq := p.buildMessageRequest(req)
	
	// 发送请求
	msgResp, err := p.sendMessageRequest(ctx, msgReq)
	if err != nil {
		return nil, err
	}
	
	// 构建响应
	response := &QueryResponse{
		ID:        fmt.Sprintf("anthropic-%d", time.Now().Unix()),
		Type:      req.Type,
		Query:     req.Query,
		Response:  p.extractTextFromResponse(msgResp),
		Confidence: 0.85, // Claude通常提供高质量的回答
		Tokens: TokenUsage{
			Prompt:     msgResp.Usage.InputTokens,
			Completion: msgResp.Usage.OutputTokens,
			Total:      msgResp.Usage.InputTokens + msgResp.Usage.OutputTokens,
		},
		Duration:  time.Since(startTime),
		Context:   req.Context,
		CreatedAt: time.Now(),
	}
	
	return response, nil
}

// AnalyzeThreat 威胁分析
func (p *anthropicProvider) AnalyzeThreat(ctx context.Context, data map[string]interface{}) (*ThreatAnalysisResult, error) {
	// 构建威胁分析提示
	prompt := p.buildThreatAnalysisPrompt(data)
	
	req := &QueryRequest{
		Type:        QueryTypeThreatAnalysis,
		Query:       prompt,
		Context:     data,
		MaxTokens:   1500,
		Temperature: 0.2, // Claude在较低温度下表现更好
	}
	
	resp, err := p.Query(ctx, req)
	if err != nil {
		return nil, err
	}
	
	// 解析威胁分析结果
	return p.parseThreatAnalysisResponse(resp.Response)
}

// GenerateIncidentResponse 生成事件响应
func (p *anthropicProvider) GenerateIncidentResponse(ctx context.Context, incident map[string]interface{}) (*IncidentResponse, error) {
	// 构建事件响应提示
	prompt := p.buildIncidentResponsePrompt(incident)
	
	req := &QueryRequest{
		Type:        QueryTypeIncidentResponse,
		Query:       prompt,
		Context:     incident,
		MaxTokens:   2000,
		Temperature: 0.3,
	}
	
	resp, err := p.Query(ctx, req)
	if err != nil {
		return nil, err
	}
	
	// 解析事件响应结果
	return p.parseIncidentResponse(resp.Response)
}

// Close 关闭提供商连接
func (p *anthropicProvider) Close() error {
	// Anthropic HTTP客户端无需特殊清理
	return nil
}

// Anthropic API数据结构
type anthropicMessageRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	Messages  []anthropicMessage `json:"messages"`
	System    string             `json:"system,omitempty"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicMessageResponse struct {
	ID           string                   `json:"id"`
	Type         string                   `json:"type"`
	Role         string                   `json:"role"`
	Content      []anthropicContent       `json:"content"`
	Model        string                   `json:"model"`
	StopReason   string                   `json:"stop_reason"`
	StopSequence interface{}              `json:"stop_sequence"`
	Usage        anthropicUsage           `json:"usage"`
}

type anthropicContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type anthropicUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// buildMessageRequest 构建消息请求
func (p *anthropicProvider) buildMessageRequest(req *QueryRequest) *anthropicMessageRequest {
	systemPrompt := p.getSystemPrompt(req.Type)
	
	messages := []anthropicMessage{
		{Role: "user", Content: req.Query},
	}
	
	maxTokens := req.MaxTokens
	if maxTokens == 0 {
		maxTokens = 2048
	}
	
	return &anthropicMessageRequest{
		Model:     p.config.Model,
		MaxTokens: maxTokens,
		Messages:  messages,
		System:    systemPrompt,
	}
}

// getSystemPrompt 获取系统提示
func (p *anthropicProvider) getSystemPrompt(queryType QueryType) string {
	switch queryType {
	case QueryTypeThreatAnalysis:
		return `你是一个资深的网络安全威胁分析专家，拥有超过15年的安全事件响应经验。你的专长包括：
- 恶意软件分析和逆向工程
- 网络流量分析和入侵检测
- 威胁情报收集和关联分析
- 高级持续威胁(APT)攻击模式识别

请基于提供的安全数据进行专业威胁分析，评估风险等级，识别攻击指标(IOCs)，并提供具体的缓解措施和响应建议。
分析应当准确、全面且可操作。`

	case QueryTypeIncidentResponse:
		return `你是一个经验丰富的网络安全事件响应专家和CISSP认证专业人士。你精通：
- 事件响应框架(NIST, SANS)
- 数字取证和证据保全
- 危机管理和沟通协调
- 业务连续性和恢复规划

请为给定的安全事件制定详细的响应计划，包括containment、eradication、recovery和lessons learned阶段。
响应计划应当符合行业最佳实践，考虑业务影响，并提供清晰的执行步骤和时间表。`

	case QueryTypeLogAnalysis:
		return `你是一个专业的安全日志分析师，擅长从大量日志数据中发现异常模式和安全威胁。你熟练掌握：
- SIEM系统和日志关联规则
- 各种日志格式和安全事件模式
- 统计分析和异常检测技术
- 威胁狩猎和主动防御策略

请详细分析提供的日志数据，识别可疑活动，解释攻击技术，并提供详细的分析报告。`

	default:
		return `你是一个专业的网络安全专家，具有深厚的安全技术背景和丰富的实战经验。
你能够准确理解各种安全相关的查询，提供专业、准确且实用的安全建议。
请确保回答具有技术深度，同时保持清晰易懂，并提供可操作的建议。`
	}
}

// sendMessageRequest 发送消息请求
func (p *anthropicProvider) sendMessageRequest(ctx context.Context, req *anthropicMessageRequest) (*anthropicMessageResponse, error) {
	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	
	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.config.BaseURL+"/messages", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", p.config.APIKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")
	
	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Anthropic API returned status %d", resp.StatusCode)
	}
	
	var msgResp anthropicMessageResponse
	if err := json.NewDecoder(resp.Body).Decode(&msgResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	
	return &msgResp, nil
}

// extractTextFromResponse 从响应中提取文本
func (p *anthropicProvider) extractTextFromResponse(resp *anthropicMessageResponse) string {
	var text strings.Builder
	
	for _, content := range resp.Content {
		if content.Type == "text" {
			text.WriteString(content.Text)
		}
	}
	
	return text.String()
}

// buildThreatAnalysisPrompt 构建威胁分析提示
func (p *anthropicProvider) buildThreatAnalysisPrompt(data map[string]interface{}) string {
	var prompt strings.Builder
	
	prompt.WriteString("## 威胁分析请求\n\n")
	prompt.WriteString("请对以下安全数据进行深度威胁分析：\n\n")
	
	// 添加数据到提示中
	prompt.WriteString("### 安全数据\n")
	for key, value := range data {
		prompt.WriteString(fmt.Sprintf("- **%s**: %v\n", key, value))
	}
	
	prompt.WriteString("\n### 分析要求\n")
	prompt.WriteString("请提供以下分析内容：\n")
	prompt.WriteString("1. **威胁等级**: 评估为 Critical/High/Medium/Low\n")
	prompt.WriteString("2. **置信度**: 提供0.0-1.0的置信度评分\n")
	prompt.WriteString("3. **威胁指标(IOCs)**: 识别具体的妥协指标\n")
	prompt.WriteString("4. **攻击技术**: 映射到MITRE ATT&CK框架\n")
	prompt.WriteString("5. **缓解措施**: 提供具体的防护建议\n")
	prompt.WriteString("6. **响应行动**: 推荐的immediate和long-term行动\n")
	
	return prompt.String()
}

// buildIncidentResponsePrompt 构建事件响应提示
func (p *anthropicProvider) buildIncidentResponsePrompt(incident map[string]interface{}) string {
	var prompt strings.Builder
	
	prompt.WriteString("## 安全事件响应计划\n\n")
	prompt.WriteString("请为以下安全事件制定全面的响应计划：\n\n")
	
	// 添加事件数据到提示中
	prompt.WriteString("### 事件详情\n")
	for key, value := range incident {
		prompt.WriteString(fmt.Sprintf("- **%s**: %v\n", key, value))
	}
	
	prompt.WriteString("\n### 响应计划要求\n")
	prompt.WriteString("请按照NIST事件响应框架提供：\n\n")
	prompt.WriteString("1. **事件分类和严重性评估**\n")
	prompt.WriteString("2. **Preparation阶段**: 准备工作清单\n")
	prompt.WriteString("3. **Detection & Analysis阶段**: 详细调查步骤\n")
	prompt.WriteString("4. **Containment阶段**: immediate和long-term隔离措施\n")
	prompt.WriteString("5. **Eradication & Recovery阶段**: 清除威胁和系统恢复\n")
	prompt.WriteString("6. **Post-Incident Activity**: 事后总结和改进建议\n")
	prompt.WriteString("7. **时间线**: 各阶段预估时间和关键里程碑\n")
	prompt.WriteString("8. **沟通计划**: 内部和外部沟通策略\n")
	
	return prompt.String()
}

// parseThreatAnalysisResponse 解析威胁分析响应
func (p *anthropicProvider) parseThreatAnalysisResponse(response string) (*ThreatAnalysisResult, error) {
	result := &ThreatAnalysisResult{
		ThreatLevel: "medium",
		Confidence:  0.7,
		Indicators:  []ThreatIndicator{},
		Mitigations: []string{},
		Actions:     []RecommendedAction{},
		Context:     map[string]interface{}{"raw_response": response},
	}
	
	// 提取威胁级别
	response = strings.ToLower(response)
	if strings.Contains(response, "critical") || strings.Contains(response, "严重") {
		result.ThreatLevel = "critical"
		result.Confidence = 0.95
	} else if strings.Contains(response, "high") || strings.Contains(response, "高") {
		result.ThreatLevel = "high"
		result.Confidence = 0.9
	} else if strings.Contains(response, "low") || strings.Contains(response, "低") {
		result.ThreatLevel = "low"
		result.Confidence = 0.8
	}
	
	// 解析缓解措施（简化版本）
	if strings.Contains(response, "block") || strings.Contains(response, "阻止") {
		result.Mitigations = append(result.Mitigations, "阻止可疑IP地址")
	}
	if strings.Contains(response, "patch") || strings.Contains(response, "补丁") {
		result.Mitigations = append(result.Mitigations, "应用安全补丁")
	}
	if strings.Contains(response, "monitor") || strings.Contains(response, "监控") {
		result.Mitigations = append(result.Mitigations, "加强监控")
	}
	
	// 解析推荐行动
	result.Actions = append(result.Actions, RecommendedAction{
		Action:     "investigate",
		Target:     "source_ip",
		Priority:   "high",
		Reason:     "需要进一步调查可疑活动",
		Confidence: 0.8,
	})
	
	return result, nil
}

// parseIncidentResponse 解析事件响应
func (p *anthropicProvider) parseIncidentResponse(response string) (*IncidentResponse, error) {
	incident := &IncidentResponse{
		IncidentID: fmt.Sprintf("claude-incident-%d", time.Now().Unix()),
		Summary:    "Claude生成的事件响应计划",
		Severity:   "medium",
		Steps:      []ResponseStep{},
		Timeline:   []TimelineEvent{},
		Context:    map[string]interface{}{"raw_response": response},
	}
	
	// 解析严重性
	response = strings.ToLower(response)
	if strings.Contains(response, "critical") || strings.Contains(response, "严重") {
		incident.Severity = "critical"
	} else if strings.Contains(response, "high") || strings.Contains(response, "高") {
		incident.Severity = "high"
	} else if strings.Contains(response, "low") || strings.Contains(response, "低") {
		incident.Severity = "low"
	}
	
	// 生成标准响应步骤
	steps := []ResponseStep{
		{Order: 1, Action: "immediate_assessment", Description: "立即评估事件影响范围", Duration: "10分钟", Owner: "值班工程师"},
		{Order: 2, Action: "containment", Description: "隔离受影响的系统", Duration: "30分钟", Owner: "SOC团队"},
		{Order: 3, Action: "evidence_preservation", Description: "保存数字证据", Duration: "1小时", Owner: "安全分析师"},
		{Order: 4, Action: "detailed_investigation", Description: "深入调查攻击路径", Duration: "4小时", Owner: "威胁分析专家"},
		{Order: 5, Action: "eradication", Description: "清除威胁和修复漏洞", Duration: "8小时", Owner: "系统管理员"},
		{Order: 6, Action: "recovery", Description: "恢复正常业务操作", Duration: "2小时", Owner: "运维团队"},
		{Order: 7, Action: "lessons_learned", Description: "事后分析和改进", Duration: "2天", Owner: "安全团队"},
	}
	
	incident.Steps = steps
	
	// 生成时间线事件
	now := time.Now()
	timeline := []TimelineEvent{
		{Timestamp: now, Event: "incident_detected", Description: "安全事件被检测", Actor: "自动化系统"},
		{Timestamp: now.Add(5 * time.Minute), Event: "response_initiated", Description: "事件响应流程启动", Actor: "SOC分析师"},
		{Timestamp: now.Add(15 * time.Minute), Event: "containment_start", Description: "开始隔离措施", Actor: "响应团队"},
	}
	
	incident.Timeline = timeline
	
	return incident, nil
}