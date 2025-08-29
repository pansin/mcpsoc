package ai

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
)

// manager AI服务管理器实现
type manager struct {
	logger          *logrus.Logger
	providers       map[string]Provider
	defaultProvider string
	mu              sync.RWMutex
}

// NewService 创建新的AI服务
func NewService(logger *logrus.Logger, config *Config) (Service, error) {
	if logger == nil {
		logger = logrus.New()
	}

	service := &manager{
		logger:          logger,
		providers:       make(map[string]Provider),
		defaultProvider: config.DefaultProvider,
	}

	// 初始化配置的提供商
	for _, providerConfig := range config.Providers {
		provider, err := createProvider(providerConfig, logger)
		if err != nil {
			logger.WithError(err).Warnf("Failed to create provider %s", providerConfig.Name)
			continue
		}

		if err := service.AddProvider(provider); err != nil {
			logger.WithError(err).Warnf("Failed to add provider %s", providerConfig.Name)
		}
	}

	return service, nil
}

// createProvider 根据配置创建提供商
func createProvider(config ProviderConfig, logger *logrus.Logger) (Provider, error) {
	switch config.Type {
	case ProviderOpenAI:
		return NewOpenAIProvider(config, logger)
	case ProviderAnthropic:
		return NewAnthropicProvider(config, logger)
	case ProviderLocal:
		return NewLocalProvider(config, logger)
	default:
		return nil, fmt.Errorf("unsupported provider type: %s", config.Type)
	}
}

// AddProvider 添加AI提供商
func (m *manager) AddProvider(provider Provider) error {
	if provider == nil {
		return fmt.Errorf("provider cannot be nil")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	name := provider.GetName()
	if _, exists := m.providers[name]; exists {
		return fmt.Errorf("provider %s already exists", name)
	}

	m.providers[name] = provider
	m.logger.WithFields(logrus.Fields{
		"provider": name,
		"type":     provider.GetType(),
	}).Info("AI provider added successfully")

	return nil
}

// GetProvider 获取指定的AI提供商
func (m *manager) GetProvider(name string) (Provider, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	provider, exists := m.providers[name]
	if !exists {
		return nil, fmt.Errorf("provider %s not found", name)
	}

	return provider, nil
}

// GetDefaultProvider 获取默认AI提供商
func (m *manager) GetDefaultProvider() (Provider, error) {
	if m.defaultProvider == "" {
		return nil, fmt.Errorf("no default provider configured")
	}

	return m.GetProvider(m.defaultProvider)
}

// ListProviders 列出所有AI提供商
func (m *manager) ListProviders() []Provider {
	m.mu.RLock()
	defer m.mu.RUnlock()

	providers := make([]Provider, 0, len(m.providers))
	for _, provider := range m.providers {
		providers = append(providers, provider)
	}

	return providers
}

// Query 使用默认提供商执行查询
func (m *manager) Query(ctx context.Context, req *QueryRequest) (*QueryResponse, error) {
	provider, err := m.GetDefaultProvider()
	if err != nil {
		return nil, err
	}

	return provider.Query(ctx, req)
}

// QueryWithProvider 使用指定提供商执行查询
func (m *manager) QueryWithProvider(ctx context.Context, providerName string, req *QueryRequest) (*QueryResponse, error) {
	provider, err := m.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	return provider.Query(ctx, req)
}

// AnalyzeThreat 威胁分析
func (m *manager) AnalyzeThreat(ctx context.Context, data map[string]interface{}) (*ThreatAnalysisResult, error) {
	provider, err := m.GetDefaultProvider()
	if err != nil {
		return nil, err
	}

	return provider.AnalyzeThreat(ctx, data)
}

// GenerateIncidentResponse 生成事件响应
func (m *manager) GenerateIncidentResponse(ctx context.Context, incident map[string]interface{}) (*IncidentResponse, error) {
	provider, err := m.GetDefaultProvider()
	if err != nil {
		return nil, err
	}

	return provider.GenerateIncidentResponse(ctx, incident)
}

// Close 关闭AI服务
func (m *manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var lastError error
	for name, provider := range m.providers {
		if err := provider.Close(); err != nil {
			m.logger.WithError(err).Warnf("Failed to close provider %s", name)
			lastError = err
		}
	}

	m.providers = make(map[string]Provider)
	m.logger.Info("AI service closed")

	return lastError
}

// ParseSecurityQuery 解析安全查询
func ParseSecurityQuery(query string) (*QueryRequest, error) {
	// 基础的查询解析逻辑
	req := NewQueryRequest(QueryTypeNaturalLanguage, query)

	// 根据关键词判断查询类型
	if containsAny(query, []string{"threat", "威胁", "攻击", "恶意"}) {
		req.Type = QueryTypeThreatAnalysis
	} else if containsAny(query, []string{"incident", "事件", "响应", "处置"}) {
		req.Type = QueryTypeIncidentResponse
	} else if containsAny(query, []string{"log", "日志", "分析"}) {
		req.Type = QueryTypeLogAnalysis
	}

	// 从查询中提取时间范围
	if timeRange := extractTimeRange(query); timeRange != "" {
		req.WithContext("time_range", timeRange)
	}

	// 提取严重性级别
	if severity := extractSeverity(query); severity != "" {
		req.WithContext("severity", severity)
	}

	return req, nil
}

// containsAny 检查字符串是否包含任意关键词
func containsAny(text string, keywords []string) bool {
	text = strings.ToLower(text)
	for _, keyword := range keywords {
		if strings.Contains(text, strings.ToLower(keyword)) {
			return true
		}
	}
	return false
}

// extractTimeRange 从查询中提取时间范围
func extractTimeRange(query string) string {
	timePatterns := map[string]string{
		"24小时":  "24h",
		"1天":    "24h", 
		"一天":    "24h",
		"1小时":   "1h",
		"一小时":   "1h",
		"1周":    "7d",
		"一周":    "7d",
		"1个月":   "30d",
		"一个月":   "30d",
	}

	query = strings.ToLower(query)
	for pattern, value := range timePatterns {
		if strings.Contains(query, pattern) {
			return value
		}
	}

	return ""
}

// extractSeverity 从查询中提取严重性级别
func extractSeverity(query string) string {
	severityPatterns := map[string]string{
		"高危": "high",
		"高级": "high", 
		"严重": "critical",
		"紧急": "critical",
		"中等": "medium",
		"中级": "medium",
		"低级": "low",
		"轻微": "low",
	}

	query = strings.ToLower(query)
	for pattern, value := range severityPatterns {
		if strings.Contains(query, pattern) {
			return value
		}
	}

	return ""
}