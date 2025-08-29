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

// localProvider 本地模型提供商实现
type localProvider struct {
	name       string
	config     ProviderConfig
	logger     *logrus.Logger
	httpClient *http.Client
}

// NewLocalProvider 创建本地模型提供商
func NewLocalProvider(config ProviderConfig, logger *logrus.Logger) (Provider, error) {
	if config.BaseURL == "" {
		config.BaseURL = "http://localhost:11434" // Ollama默认地址
	}

	if config.Model == "" {
		config.Model = "llama2" // 默认模型
	}

	return &localProvider{
		name:       config.Name,
		config:     config,
		logger:     logger,
		httpClient: &http.Client{Timeout: 120 * time.Second}, // 本地模型可能需要更长时间
	}, nil
}

// GetName 获取提供商名称
func (p *localProvider) GetName() string {
	return p.name
}

// GetType 获取提供商类型
func (p *localProvider) GetType() ProviderType {
	return ProviderLocal
}

// IsAvailable 检查服务是否可用
func (p *localProvider) IsAvailable(ctx context.Context) bool {
	// 检查Ollama服务是否运行
	req, err := http.NewRequestWithContext(ctx, "GET", p.config.BaseURL+"/api/tags", nil)
	if err != nil {
		return false
	}
	
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	return resp.StatusCode == http.StatusOK
}

// Query 执行AI查询
func (p *localProvider) Query(ctx context.Context, req *QueryRequest) (*QueryResponse, error) {
	startTime := time.Now()
	
	// 构建Ollama API请求
	generateReq := p.buildGenerateRequest(req)
	
	// 发送请求
	generateResp, err := p.sendGenerateRequest(ctx, generateReq)
	if err != nil {
		return nil, err
	}
	
	// 构建响应
	response := &QueryResponse{
		ID:        fmt.Sprintf("local-%d", time.Now().Unix()),
		Type:      req.Type,
		Query:     req.Query,
		Response:  generateResp.Response,
		Confidence: 0.75, // 本地模型的置信度可能略低
		Tokens: TokenUsage{
			Prompt:     generateResp.PromptEvalCount,
			Completion: generateResp.EvalCount,
			Total:      generateResp.PromptEvalCount + generateResp.EvalCount,
		},
		Duration:  time.Since(startTime),
		Context:   req.Context,
		CreatedAt: time.Now(),
	}
	
	return response, nil
}

// AnalyzeThreat 威胁分析
func (p *localProvider) AnalyzeThreat(ctx context.Context, data map[string]interface{}) (*ThreatAnalysisResult, error) {
	// 构建威胁分析提示
	prompt := p.buildThreatAnalysisPrompt(data)
	
	req := &QueryRequest{
		Type:        QueryTypeThreatAnalysis,
		Query:       prompt,
		Context:     data,
		MaxTokens:   1000, // 本地模型可能处理能力有限
		Temperature: 0.1,  // 较低的温度以获得更一致的结果
	}
	
	resp, err := p.Query(ctx, req)
	if err != nil {
		return nil, err
	}
	
	// 解析威胁分析结果
	return p.parseThreatAnalysisResponse(resp.Response)
}

// GenerateIncidentResponse 生成事件响应
func (p *localProvider) GenerateIncidentResponse(ctx context.Context, incident map[string]interface{}) (*IncidentResponse, error) {
	// 构建事件响应提示
	prompt := p.buildIncidentResponsePrompt(incident)
	
	req := &QueryRequest{
		Type:        QueryTypeIncidentResponse,
		Query:       prompt,
		Context:     incident,
		MaxTokens:   1500,
		Temperature: 0.2,
	}
	
	resp, err := p.Query(ctx, req)
	if err != nil {
		return nil, err
	}
	
	// 解析事件响应结果
	return p.parseIncidentResponse(resp.Response)
}

// Close 关闭提供商连接
func (p *localProvider) Close() error {
	// 本地HTTP客户端无需特殊清理
	return nil
}

// Ollama API数据结构
type ollamaGenerateRequest struct {
	Model       string                 `json:"model"`
	Prompt      string                 `json:"prompt"`
	System      string                 `json:"system,omitempty"`
	Template    string                 `json:"template,omitempty"`
	Context     []int                  `json:"context,omitempty"`
	Stream      bool                   `json:"stream"`
	Raw         bool                   `json:"raw,omitempty"`
	Format      string                 `json:"format,omitempty"`
	Options     map[string]interface{} `json:"options,omitempty"`
}

type ollamaGenerateResponse struct {
	Model              string    `json:"model"`
	CreatedAt          time.Time `json:"created_at"`
	Response           string    `json:"response"`
	Done               bool      `json:"done"`
	Context            []int     `json:"context"`
	TotalDuration      int64     `json:"total_duration"`
	LoadDuration       int64     `json:"load_duration"`
	PromptEvalCount    int       `json:"prompt_eval_count"`
	PromptEvalDuration int64     `json:"prompt_eval_duration"`
	EvalCount          int       `json:"eval_count"`
	EvalDuration       int64     `json:"eval_duration"`
}

// buildGenerateRequest 构建生成请求
func (p *localProvider) buildGenerateRequest(req *QueryRequest) *ollamaGenerateRequest {
	systemPrompt := p.getSystemPrompt(req.Type)
	
	options := make(map[string]interface{})
	
	// 设置温度
	if req.Temperature > 0 {
		options["temperature"] = req.Temperature
	} else {
		options["temperature"] = 0.7
	}
	
	// 设置最大token数
	if req.MaxTokens > 0 {
		options["num_predict"] = req.MaxTokens
	}
	
	return &ollamaGenerateRequest{
		Model:   p.config.Model,
		Prompt:  req.Query,
		System:  systemPrompt,
		Stream:  false,
		Options: options,
	}
}

// getSystemPrompt 获取系统提示
func (p *localProvider) getSystemPrompt(queryType QueryType) string {
	switch queryType {
	case QueryTypeThreatAnalysis:
		return `You are a cybersecurity threat analyst with expertise in security incident analysis.
Analyze the provided security data and identify potential threats.
Provide threat level assessment, confidence score, and mitigation recommendations.
Keep responses concise and actionable.`

	case QueryTypeIncidentResponse:
		return `You are a cybersecurity incident response specialist.
Create detailed response plans for security incidents following industry best practices.
Include containment, eradication, recovery steps and timeline.
Focus on practical, step-by-step guidance.`

	case QueryTypeLogAnalysis:
		return `You are a security log analyst skilled at identifying suspicious patterns.
Analyze the provided log data to identify potential security threats.
Explain attack techniques and provide detailed analysis reports.`

	default:
		return `You are a cybersecurity expert assistant.
Provide accurate, detailed and actionable security advice.
Use professional terminology while keeping explanations clear.`
	}
}

// sendGenerateRequest 发送生成请求
func (p *localProvider) sendGenerateRequest(ctx context.Context, req *ollamaGenerateRequest) (*ollamaGenerateResponse, error) {
	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	
	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.config.BaseURL+"/api/generate", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	httpReq.Header.Set("Content-Type", "application/json")
	
	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Ollama API returned status %d", resp.StatusCode)
	}
	
	var generateResp ollamaGenerateResponse
	if err := json.NewDecoder(resp.Body).Decode(&generateResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	
	return &generateResp, nil
}

// buildThreatAnalysisPrompt 构建威胁分析提示
func (p *localProvider) buildThreatAnalysisPrompt(data map[string]interface{}) string {
	var prompt strings.Builder
	
	prompt.WriteString("Analyze the following security data for potential threats:\n\n")
	
	// 添加数据到提示中
	for key, value := range data {
		prompt.WriteString(fmt.Sprintf("%s: %v\n", key, value))
	}
	
	prompt.WriteString("\nProvide:\n")
	prompt.WriteString("1. Threat level (low/medium/high/critical)\n")
	prompt.WriteString("2. Confidence score (0.0-1.0)\n")
	prompt.WriteString("3. Threat indicators (IOCs)\n")
	prompt.WriteString("4. Mitigation recommendations\n")
	prompt.WriteString("5. Recommended actions\n")
	
	return prompt.String()
}

// buildIncidentResponsePrompt 构建事件响应提示
func (p *localProvider) buildIncidentResponsePrompt(incident map[string]interface{}) string {
	var prompt strings.Builder
	
	prompt.WriteString("Create an incident response plan for the following security event:\n\n")
	
	// 添加事件数据到提示中
	for key, value := range incident {
		prompt.WriteString(fmt.Sprintf("%s: %v\n", key, value))
	}
	
	prompt.WriteString("\nProvide structured incident response plan including:\n")
	prompt.WriteString("1. Incident summary and severity assessment\n")
	prompt.WriteString("2. Immediate containment steps\n")
	prompt.WriteString("3. Detailed investigation procedures\n")
	prompt.WriteString("4. Recovery and monitoring measures\n")
	prompt.WriteString("5. Timeline with key milestones\n")
	
	return prompt.String()
}

// parseThreatAnalysisResponse 解析威胁分析响应
func (p *localProvider) parseThreatAnalysisResponse(response string) (*ThreatAnalysisResult, error) {
	result := &ThreatAnalysisResult{
		ThreatLevel: "medium",
		Confidence:  0.6, // 本地模型的默认置信度较低
		Indicators:  []ThreatIndicator{},
		Mitigations: []string{},
		Actions:     []RecommendedAction{},
		Context:     map[string]interface{}{"raw_response": response},
	}
	
	// 提取威胁级别
	response = strings.ToLower(response)
	if strings.Contains(response, "critical") {
		result.ThreatLevel = "critical"
		result.Confidence = 0.8
	} else if strings.Contains(response, "high") {
		result.ThreatLevel = "high"
		result.Confidence = 0.75
	} else if strings.Contains(response, "low") {
		result.ThreatLevel = "low"
		result.Confidence = 0.7
	}
	
	// 基础的缓解措施解析
	mitigations := []string{}
	if strings.Contains(response, "block") || strings.Contains(response, "firewall") {
		mitigations = append(mitigations, "Block suspicious IP addresses")
	}
	if strings.Contains(response, "patch") || strings.Contains(response, "update") {
		mitigations = append(mitigations, "Apply security patches")
	}
	if strings.Contains(response, "monitor") {
		mitigations = append(mitigations, "Enhance monitoring")
	}
	if strings.Contains(response, "isolate") {
		mitigations = append(mitigations, "Isolate affected systems")
	}
	
	result.Mitigations = mitigations
	
	// 基础的推荐行动
	result.Actions = []RecommendedAction{
		{
			Action:     "investigate",
			Target:     "security_logs",
			Priority:   "medium",
			Reason:     "Further investigation required",
			Confidence: 0.7,
		},
	}
	
	return result, nil
}

// parseIncidentResponse 解析事件响应
func (p *localProvider) parseIncidentResponse(response string) (*IncidentResponse, error) {
	incident := &IncidentResponse{
		IncidentID: fmt.Sprintf("local-incident-%d", time.Now().Unix()),
		Summary:    "Local model generated incident response",
		Severity:   "medium",
		Steps:      []ResponseStep{},
		Timeline:   []TimelineEvent{},
		Context:    map[string]interface{}{"raw_response": response},
	}
	
	// 解析严重性
	response = strings.ToLower(response)
	if strings.Contains(response, "critical") || strings.Contains(response, "severe") {
		incident.Severity = "critical"
	} else if strings.Contains(response, "high") {
		incident.Severity = "high"
	} else if strings.Contains(response, "low") || strings.Contains(response, "minor") {
		incident.Severity = "low"
	}
	
	// 生成标准响应步骤
	steps := []ResponseStep{
		{Order: 1, Action: "assess", Description: "Assess incident impact and scope", Duration: "15 minutes", Owner: "SOC Analyst"},
		{Order: 2, Action: "contain", Description: "Contain the threat", Duration: "30 minutes", Owner: "Security Team"},
		{Order: 3, Action: "investigate", Description: "Detailed investigation", Duration: "2 hours", Owner: "Threat Analyst"},
		{Order: 4, Action: "remediate", Description: "Remove threats and restore services", Duration: "4 hours", Owner: "IT Team"},
		{Order: 5, Action: "monitor", Description: "Monitor for recurring threats", Duration: "24 hours", Owner: "SOC Team"},
	}
	
	incident.Steps = steps
	
	return incident, nil
}

// GetModelList 获取可用模型列表（Ollama特有功能）
func (p *localProvider) GetModelList(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", p.config.BaseURL+"/api/tags", nil)
	if err != nil {
		return nil, err
	}
	
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get model list: status %d", resp.StatusCode)
	}
	
	var tagsResp struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&tagsResp); err != nil {
		return nil, err
	}
	
	models := make([]string, len(tagsResp.Models))
	for i, model := range tagsResp.Models {
		models[i] = model.Name
	}
	
	return models, nil
}