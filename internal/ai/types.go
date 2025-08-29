package ai

import (
	"context"
	"time"
)

// Provider AI提供商类型
type ProviderType string

const (
	ProviderOpenAI    ProviderType = "openai"
	ProviderAnthropic ProviderType = "anthropic"
	ProviderLocal     ProviderType = "local"
)

// QueryType 查询类型
type QueryType string

const (
	QueryTypeNaturalLanguage QueryType = "natural_language"
	QueryTypeThreatAnalysis  QueryType = "threat_analysis"
	QueryTypeIncidentResponse QueryType = "incident_response"
	QueryTypeLogAnalysis     QueryType = "log_analysis"
)

// QueryRequest AI查询请求
type QueryRequest struct {
	Type        QueryType              `json:"type"`
	Query       string                 `json:"query"`
	Context     map[string]interface{} `json:"context,omitempty"`
	SessionID   string                 `json:"session_id,omitempty"`
	MaxTokens   int                    `json:"max_tokens,omitempty"`
	Temperature float32                `json:"temperature,omitempty"`
}

// QueryResponse AI查询响应
type QueryResponse struct {
	ID           string                 `json:"id"`
	Type         QueryType              `json:"type"`
	Query        string                 `json:"query"`
	Response     string                 `json:"response"`
	Confidence   float64                `json:"confidence"`
	Tokens       TokenUsage             `json:"tokens"`
	Duration     time.Duration          `json:"duration"`
	Context      map[string]interface{} `json:"context,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt    time.Time              `json:"created_at"`
}

// TokenUsage 令牌使用统计
type TokenUsage struct {
	Prompt     int `json:"prompt"`
	Completion int `json:"completion"`
	Total      int `json:"total"`
}

// ThreatAnalysisResult 威胁分析结果
type ThreatAnalysisResult struct {
	ThreatLevel   string                 `json:"threat_level"`    // low, medium, high, critical
	Confidence    float64                `json:"confidence"`      // 0.0 - 1.0
	Indicators    []ThreatIndicator      `json:"indicators"`
	Mitigations   []string               `json:"mitigations"`
	Actions       []RecommendedAction    `json:"actions"`
	Context       map[string]interface{} `json:"context,omitempty"`
}

// ThreatIndicator 威胁指标
type ThreatIndicator struct {
	Type        string  `json:"type"`        // ip, domain, hash, etc.
	Value       string  `json:"value"`
	Confidence  float64 `json:"confidence"`
	Source      string  `json:"source"`
	Description string  `json:"description"`
}

// RecommendedAction 推荐行动
type RecommendedAction struct {
	Action      string  `json:"action"`
	Target      string  `json:"target"`
	Priority    string  `json:"priority"`   // low, medium, high, urgent
	Reason      string  `json:"reason"`
	Confidence  float64 `json:"confidence"`
}

// IncidentResponse 事件响应
type IncidentResponse struct {
	IncidentID   string                 `json:"incident_id"`
	Summary      string                 `json:"summary"`
	Severity     string                 `json:"severity"`
	Steps        []ResponseStep         `json:"steps"`
	Timeline     []TimelineEvent       `json:"timeline"`
	Context      map[string]interface{} `json:"context,omitempty"`
}

// ResponseStep 响应步骤
type ResponseStep struct {
	Order       int    `json:"order"`
	Action      string `json:"action"`
	Description string `json:"description"`
	Duration    string `json:"duration"`
	Owner       string `json:"owner"`
}

// TimelineEvent 时间线事件
type TimelineEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	Event       string    `json:"event"`
	Description string    `json:"description"`
	Actor       string    `json:"actor"`
}

// Provider AI提供商接口
type Provider interface {
	// GetName 获取提供商名称
	GetName() string
	
	// GetType 获取提供商类型
	GetType() ProviderType
	
	// IsAvailable 检查服务是否可用
	IsAvailable(ctx context.Context) bool
	
	// Query 执行AI查询
	Query(ctx context.Context, req *QueryRequest) (*QueryResponse, error)
	
	// AnalyzeThreat 威胁分析
	AnalyzeThreat(ctx context.Context, data map[string]interface{}) (*ThreatAnalysisResult, error)
	
	// GenerateIncidentResponse 生成事件响应
	GenerateIncidentResponse(ctx context.Context, incident map[string]interface{}) (*IncidentResponse, error)
	
	// Close 关闭提供商连接
	Close() error
}

// Service AI服务管理器
type Service interface {
	// AddProvider 添加AI提供商
	AddProvider(provider Provider) error
	
	// GetProvider 获取指定的AI提供商
	GetProvider(name string) (Provider, error)
	
	// GetDefaultProvider 获取默认AI提供商
	GetDefaultProvider() (Provider, error)
	
	// ListProviders 列出所有AI提供商
	ListProviders() []Provider
	
	// Query 使用默认提供商执行查询
	Query(ctx context.Context, req *QueryRequest) (*QueryResponse, error)
	
	// QueryWithProvider 使用指定提供商执行查询
	QueryWithProvider(ctx context.Context, providerName string, req *QueryRequest) (*QueryResponse, error)
	
	// AnalyzeThreat 威胁分析
	AnalyzeThreat(ctx context.Context, data map[string]interface{}) (*ThreatAnalysisResult, error)
	
	// GenerateIncidentResponse 生成事件响应
	GenerateIncidentResponse(ctx context.Context, incident map[string]interface{}) (*IncidentResponse, error)
	
	// Close 关闭AI服务
	Close() error
}

// Config AI服务配置
type Config struct {
	DefaultProvider string           `json:"default_provider"`
	Providers       []ProviderConfig `json:"providers"`
}

// ProviderConfig AI提供商配置
type ProviderConfig struct {
	Name        string            `json:"name"`
	Type        ProviderType      `json:"type"`
	APIKey      string            `json:"api_key"`
	Model       string            `json:"model"`
	BaseURL     string            `json:"base_url,omitempty"`
	MaxTokens   int               `json:"max_tokens,omitempty"`
	Temperature float32           `json:"temperature,omitempty"`
	Options     map[string]string `json:"options,omitempty"`
}

// Error types
type Error struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Code    int    `json:"code,omitempty"`
}

func (e *Error) Error() string {
	return e.Message
}

// Common error types
var (
	ErrProviderNotFound     = &Error{Type: "provider_not_found", Message: "AI provider not found"}
	ErrProviderUnavailable  = &Error{Type: "provider_unavailable", Message: "AI provider is unavailable"}
	ErrInvalidRequest       = &Error{Type: "invalid_request", Message: "Invalid AI request"}
	ErrRateLimited          = &Error{Type: "rate_limited", Message: "Request rate limited"}
	ErrInsufficientCredits  = &Error{Type: "insufficient_credits", Message: "Insufficient API credits"}
	ErrModelNotSupported    = &Error{Type: "model_not_supported", Message: "Model not supported"}
)

// Utility functions

// NewQueryRequest 创建新的查询请求
func NewQueryRequest(queryType QueryType, query string) *QueryRequest {
	return &QueryRequest{
		Type:        queryType,
		Query:       query,
		Context:     make(map[string]interface{}),
		MaxTokens:   2048,
		Temperature: 0.7,
	}
}

// WithContext 添加上下文
func (req *QueryRequest) WithContext(key string, value interface{}) *QueryRequest {
	if req.Context == nil {
		req.Context = make(map[string]interface{})
	}
	req.Context[key] = value
	return req
}

// WithSessionID 设置会话ID
func (req *QueryRequest) WithSessionID(sessionID string) *QueryRequest {
	req.SessionID = sessionID
	return req
}

// WithMaxTokens 设置最大令牌数
func (req *QueryRequest) WithMaxTokens(maxTokens int) *QueryRequest {
	req.MaxTokens = maxTokens
	return req
}

// WithTemperature 设置温度参数
func (req *QueryRequest) WithTemperature(temperature float32) *QueryRequest {
	req.Temperature = temperature
	return req
}