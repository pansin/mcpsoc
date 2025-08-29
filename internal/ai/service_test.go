package ai

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockProvider 模拟AI提供商
type MockProvider struct {
	mock.Mock
}

func (m *MockProvider) GetName() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockProvider) GetType() ProviderType {
	args := m.Called()
	return args.Get(0).(ProviderType)
}

func (m *MockProvider) IsAvailable(ctx context.Context) bool {
	args := m.Called(ctx)
	return args.Bool(0)
}

func (m *MockProvider) Query(ctx context.Context, req *QueryRequest) (*QueryResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*QueryResponse), args.Error(1)
}

func (m *MockProvider) AnalyzeThreat(ctx context.Context, data map[string]interface{}) (*ThreatAnalysisResult, error) {
	args := m.Called(ctx, data)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ThreatAnalysisResult), args.Error(1)
}

func (m *MockProvider) GenerateIncidentResponse(ctx context.Context, incident map[string]interface{}) (*IncidentResponse, error) {
	args := m.Called(ctx, incident)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*IncidentResponse), args.Error(1)
}

func (m *MockProvider) Close() error {
	args := m.Called()
	return args.Error(0)
}

func TestNewService(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	config := &Config{
		DefaultProvider: "mock",
		Providers: []ProviderConfig{
			{
				Name: "mock",
				Type: ProviderOpenAI,
			},
		},
	}

	service, err := NewService(logger, config)
	require.NoError(t, err)
	require.NotNil(t, service)
}

func TestManager_AddProvider(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	config := &Config{
		DefaultProvider: "test",
		Providers:       []ProviderConfig{},
	}

	service, err := NewService(logger, config)
	require.NoError(t, err)

	manager := service.(*manager)

	// 创建模拟提供商
	mockProvider := &MockProvider{}
	mockProvider.On("GetName").Return("test-provider")
	mockProvider.On("GetType").Return(ProviderOpenAI)

	// 测试添加提供商
	err = manager.AddProvider(mockProvider)
	assert.NoError(t, err)

	// 验证提供商已添加
	provider, err := manager.GetProvider("test-provider")
	assert.NoError(t, err)
	assert.Equal(t, mockProvider, provider)

	// 测试重复添加
	err = manager.AddProvider(mockProvider)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestManager_GetProvider(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	config := &Config{
		DefaultProvider: "test",
		Providers:       []ProviderConfig{},
	}

	service, err := NewService(logger, config)
	require.NoError(t, err)

	manager := service.(*manager)

	// 测试获取不存在的提供商
	provider, err := manager.GetProvider("nonexistent")
	assert.Error(t, err)
	assert.Nil(t, provider)
	assert.Contains(t, err.Error(), "not found")
}

func TestManager_Query(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	config := &Config{
		DefaultProvider: "test-provider",
		Providers:       []ProviderConfig{},
	}

	service, err := NewService(logger, config)
	require.NoError(t, err)

	manager := service.(*manager)

	// 创建模拟提供商
	mockProvider := &MockProvider{}
	mockProvider.On("GetName").Return("test-provider")
	mockProvider.On("GetType").Return(ProviderOpenAI)

	// 添加提供商
	err = manager.AddProvider(mockProvider)
	require.NoError(t, err)

	// 设置模拟查询响应
	expectedResponse := &QueryResponse{
		ID:        "test-query-1",
		Type:      QueryTypeNaturalLanguage,
		Query:     "test query",
		Response:  "test response",
		Confidence: 0.8,
		CreatedAt: time.Now(),
	}

	mockProvider.On("Query", mock.Anything, mock.AnythingOfType("*ai.QueryRequest")).Return(expectedResponse, nil)

	// 执行查询
	ctx := context.Background()
	req := NewQueryRequest(QueryTypeNaturalLanguage, "test query")
	
	response, err := manager.Query(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, expectedResponse, response)

	mockProvider.AssertExpectations(t)
}

func TestManager_AnalyzeThreat(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	config := &Config{
		DefaultProvider: "threat-analyzer",
		Providers:       []ProviderConfig{},
	}

	service, err := NewService(logger, config)
	require.NoError(t, err)

	manager := service.(*manager)

	// 创建模拟提供商
	mockProvider := &MockProvider{}
	mockProvider.On("GetName").Return("threat-analyzer")
	mockProvider.On("GetType").Return(ProviderAnthropic)

	// 添加提供商
	err = manager.AddProvider(mockProvider)
	require.NoError(t, err)

	// 设置模拟威胁分析响应
	expectedResult := &ThreatAnalysisResult{
		ThreatLevel: "high",
		Confidence:  0.9,
		Indicators: []ThreatIndicator{
			{
				Type:        "ip",
				Value:       "192.168.1.100",
				Confidence:  0.95,
				Source:      "AI analysis",
				Description: "Suspicious IP address",
			},
		},
		Mitigations: []string{"Block IP address"},
		Actions: []RecommendedAction{
			{
				Action:     "block_ip",
				Target:     "192.168.1.100",
				Priority:   "high",
				Reason:     "Malicious activity detected",
				Confidence: 0.9,
			},
		},
	}

	mockProvider.On("AnalyzeThreat", mock.Anything, mock.AnythingOfType("map[string]interface {}")).Return(expectedResult, nil)

	// 执行威胁分析
	ctx := context.Background()
	data := map[string]interface{}{
		"source_ip": "192.168.1.100",
		"event_type": "connection_blocked",
	}
	
	result, err := manager.AnalyzeThreat(ctx, data)
	require.NoError(t, err)
	assert.Equal(t, expectedResult, result)

	mockProvider.AssertExpectations(t)
}

func TestParseSecurityQuery(t *testing.T) {
	tests := []struct {
		name           string
		query          string
		expectedType   QueryType
		expectedContext map[string]interface{}
	}{
		{
			name:         "threat analysis query",
			query:        "检查这个IP是否有威胁",
			expectedType: QueryTypeThreatAnalysis,
		},
		{
			name:         "incident response query",
			query:        "如何处理这个安全事件",
			expectedType: QueryTypeIncidentResponse,
		},
		{
			name:         "log analysis query",
			query:        "分析这些日志数据",
			expectedType: QueryTypeLogAnalysis,
		},
		{
			name:         "general security query",
			query:        "什么是最佳的安全实践",
			expectedType: QueryTypeNaturalLanguage,
		},
		{
			name:         "query with time range",
			query:        "查找过去24小时内的攻击",
			expectedType: QueryTypeNaturalLanguage,
			expectedContext: map[string]interface{}{
				"time_range": "24h",
			},
		},
		{
			name:         "query with severity",
			query:        "显示所有高危威胁",
			expectedType: QueryTypeThreatAnalysis,
			expectedContext: map[string]interface{}{
				"severity": "high",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := ParseSecurityQuery(tt.query)
			require.NoError(t, err)
			
			assert.Equal(t, tt.expectedType, req.Type)
			assert.Equal(t, tt.query, req.Query)
			
			if tt.expectedContext != nil {
				for key, expectedValue := range tt.expectedContext {
					actualValue, exists := req.Context[key]
					assert.True(t, exists, "Expected context key %s not found", key)
					assert.Equal(t, expectedValue, actualValue)
				}
			}
		})
	}
}

func TestQueryRequest_Builders(t *testing.T) {
	req := NewQueryRequest(QueryTypeThreatAnalysis, "test query")
	
	// 测试链式调用
	req.WithContext("test_key", "test_value").
		WithSessionID("session-123").
		WithMaxTokens(1000).
		WithTemperature(0.5)
	
	assert.Equal(t, QueryTypeThreatAnalysis, req.Type)
	assert.Equal(t, "test query", req.Query)
	assert.Equal(t, "test_value", req.Context["test_key"])
	assert.Equal(t, "session-123", req.SessionID)
	assert.Equal(t, 1000, req.MaxTokens)
	assert.Equal(t, float32(0.5), req.Temperature)
}

func TestManager_Close(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	config := &Config{
		DefaultProvider: "test",
		Providers:       []ProviderConfig{},
	}

	service, err := NewService(logger, config)
	require.NoError(t, err)

	manager := service.(*manager)

	// 创建模拟提供商
	mockProvider := &MockProvider{}
	mockProvider.On("GetName").Return("test-provider")
	mockProvider.On("GetType").Return(ProviderOpenAI)
	mockProvider.On("Close").Return(nil)

	// 添加提供商
	err = manager.AddProvider(mockProvider)
	require.NoError(t, err)

	// 关闭服务
	err = manager.Close()
	assert.NoError(t, err)

	// 验证提供商的Close方法被调用
	mockProvider.AssertExpectations(t)

	// 验证提供商已被清空
	providers := manager.ListProviders()
	assert.Empty(t, providers)
}

// Benchmark tests
func BenchmarkParseSecurityQuery(b *testing.B) {
	query := "检查过去24小时内的高危威胁事件"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ParseSecurityQuery(query)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkQueryRequest_WithContext(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := NewQueryRequest(QueryTypeNaturalLanguage, "test")
		req.WithContext("key1", "value1").
			WithContext("key2", "value2").
			WithContext("key3", "value3")
	}
}