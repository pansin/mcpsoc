package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mcpsoc/mcpsoc/internal/api"
	"github.com/mcpsoc/mcpsoc/internal/config"
	"github.com/mcpsoc/mcpsoc/internal/logger"
	"github.com/mcpsoc/mcpsoc/internal/mcp"
	"github.com/mcpsoc/mcpsoc/internal/storage"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// IntegrationTestSuite 集成测试套件
type IntegrationTestSuite struct {
	suite.Suite
	server     *httptest.Server
	router     *gin.Engine
	mcpManager *mcp.Manager
	db         storage.Database
	logger     *logrus.Logger
}

// SetupSuite 在所有测试前运行一次
func (s *IntegrationTestSuite) SetupSuite() {
	// 设置测试模式
	gin.SetMode(gin.TestMode)

	// 初始化日志
	s.logger = logger.New("error")

	// 初始化模拟数据库（实际项目中可能需要测试数据库）
	s.db = &MockDatabase{}

	// 初始化MCP管理器
	s.mcpManager = mcp.NewManager(s.logger)

	// 设置路由
	s.router = gin.New()
	s.setupRoutes()

	// 创建测试服务器
	s.server = httptest.NewServer(s.router)
}

// TearDownSuite 在所有测试后运行一次
func (s *IntegrationTestSuite) TearDownSuite() {
	if s.server != nil {
		s.server.Close()
	}
	if s.mcpManager != nil {
		s.mcpManager.Close()
	}
}

// SetupTest 在每个测试前运行
func (s *IntegrationTestSuite) SetupTest() {
	// 测试前的准备工作
}

// TearDownTest 在每个测试后运行
func (s *IntegrationTestSuite) TearDownTest() {
	// 测试后的清理工作
}

func (s *IntegrationTestSuite) setupRoutes() {
	apiHandler := api.NewHandler(s.logger, s.db, s.mcpManager)

	// 健康检查
	s.router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"version": "test",
			"time":    time.Now().UTC(),
		})
	})

	// API路由
	v1 := s.router.Group("/api/v1")
	{
		v1.POST("/query/natural", apiHandler.HandleNaturalQuery)
		v1.POST("/query/structured", apiHandler.HandleStructuredQuery)
		v1.GET("/mcp/servers", apiHandler.ListMCPServers)
		v1.GET("/mcp/servers/:id", apiHandler.GetMCPServer)
		v1.POST("/mcp/servers/:id/tools/:tool", apiHandler.CallMCPTool)
	}
}

// TestHealthCheck 测试健康检查端点
func (s *IntegrationTestSuite) TestHealthCheck() {
	resp, err := http.Get(s.server.URL + "/health")
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Equal(s.T(), http.StatusOK, resp.StatusCode)

	var response map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&response)
	require.NoError(s.T(), err)

	assert.Equal(s.T(), "healthy", response["status"])
	assert.Equal(s.T(), "test", response["version"])
	assert.NotNil(s.T(), response["time"])
}

// TestNaturalQueryAPI 测试自然语言查询API
func (s *IntegrationTestSuite) TestNaturalQueryAPI() {
	requestBody := api.NaturalQueryRequest{
		Query:     "查找过去24小时内的高危威胁事件",
		Context:   map[string]interface{}{"time_range": "24h"},
		SessionID: "test-session",
	}

	jsonBody, err := json.Marshal(requestBody)
	require.NoError(s.T(), err)

	resp, err := http.Post(
		s.server.URL+"/api/v1/query/natural",
		"application/json",
		bytes.NewBuffer(jsonBody),
	)
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Equal(s.T(), http.StatusOK, resp.StatusCode)

	var response api.NaturalQueryResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	require.NoError(s.T(), err)

	assert.NotEmpty(s.T(), response.QueryID)
	assert.Equal(s.T(), "completed", response.Status)
	assert.NotNil(s.T(), response.Result)
	assert.Greater(s.T(), response.ExecutionTime, 0.0)
}

// TestStructuredQueryAPI 测试结构化查询API
func (s *IntegrationTestSuite) TestStructuredQueryAPI() {
	requestBody := api.StructuredQueryRequest{
		DataSource: "security_events",
		Filters: map[string]interface{}{
			"severity": "high",
		},
		Limit:  10,
		Offset: 0,
	}

	jsonBody, err := json.Marshal(requestBody)
	require.NoError(s.T(), err)

	resp, err := http.Post(
		s.server.URL+"/api/v1/query/structured",
		"application/json",
		bytes.NewBuffer(jsonBody),
	)
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Equal(s.T(), http.StatusOK, resp.StatusCode)

	var response api.StructuredQueryResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	require.NoError(s.T(), err)

	assert.GreaterOrEqual(s.T(), response.TotalCount, int64(0))
	assert.NotNil(s.T(), response.Data)
	assert.Greater(s.T(), response.ExecutionTime, 0.0)
}

// TestMCPServersAPI 测试MCP服务器API
func (s *IntegrationTestSuite) TestMCPServersAPI() {
	// 测试获取服务器列表
	resp, err := http.Get(s.server.URL + "/api/v1/mcp/servers")
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Equal(s.T(), http.StatusOK, resp.StatusCode)

	var response map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&response)
	require.NoError(s.T(), err)

	servers, ok := response["servers"].([]interface{})
	assert.True(s.T(), ok)
	assert.GreaterOrEqual(s.T(), len(servers), 0)
}

// TestEndToEndWorkflow 端到端工作流程测试
func (s *IntegrationTestSuite) TestEndToEndWorkflow() {
	// 1. 检查系统健康状态
	resp, err := http.Get(s.server.URL + "/health")
	require.NoError(s.T(), err)
	resp.Body.Close()
	assert.Equal(s.T(), http.StatusOK, resp.StatusCode)

	// 2. 获取MCP服务器列表
	resp, err = http.Get(s.server.URL + "/api/v1/mcp/servers")
	require.NoError(s.T(), err)
	resp.Body.Close()
	assert.Equal(s.T(), http.StatusOK, resp.StatusCode)

	// 3. 执行自然语言查询
	queryBody := api.NaturalQueryRequest{
		Query:   "检查防火墙日志中的可疑活动",
		Context: map[string]interface{}{"source": "firewall"},
	}
	jsonBody, _ := json.Marshal(queryBody)

	resp, err = http.Post(
		s.server.URL+"/api/v1/query/natural",
		"application/json",
		bytes.NewBuffer(jsonBody),
	)
	require.NoError(s.T(), err)
	defer resp.Body.Close()
	assert.Equal(s.T(), http.StatusOK, resp.StatusCode)

	var queryResponse api.NaturalQueryResponse
	err = json.NewDecoder(resp.Body).Decode(&queryResponse)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), "completed", queryResponse.Status)

	// 4. 执行结构化查询
	structuredBody := api.StructuredQueryRequest{
		DataSource: "security_events",
		Filters:    map[string]interface{}{"event_type": "connection_blocked"},
		Limit:      5,
	}
	jsonBody, _ = json.Marshal(structuredBody)

	resp, err = http.Post(
		s.server.URL+"/api/v1/query/structured",
		"application/json",
		bytes.NewBuffer(jsonBody),
	)
	require.NoError(s.T(), err)
	defer resp.Body.Close()
	assert.Equal(s.T(), http.StatusOK, resp.StatusCode)

	s.T().Log("端到端工作流程测试完成")
}

// TestConcurrentRequests 并发请求测试
func (s *IntegrationTestSuite) TestConcurrentRequests() {
	const numRequests = 10
	results := make(chan error, numRequests)

	for i := 0; i < numRequests; i++ {
		go func(requestID int) {
			queryBody := api.NaturalQueryRequest{
				Query:     fmt.Sprintf("测试查询 %d", requestID),
				SessionID: fmt.Sprintf("session-%d", requestID),
			}
			jsonBody, _ := json.Marshal(queryBody)

			resp, err := http.Post(
				s.server.URL+"/api/v1/query/natural",
				"application/json",
				bytes.NewBuffer(jsonBody),
			)
			if err != nil {
				results <- err
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				results <- fmt.Errorf("unexpected status code: %d", resp.StatusCode)
				return
			}

			results <- nil
		}(i)
	}

	// 收集结果
	for i := 0; i < numRequests; i++ {
		select {
		case err := <-results:
			assert.NoError(s.T(), err, "并发请求 %d 失败", i)
		case <-time.After(30 * time.Second):
			s.T().Fatalf("并发测试超时")
		}
	}
}

// TestErrorHandling 错误处理测试
func (s *IntegrationTestSuite) TestErrorHandling() {
	// 测试无效的JSON
	resp, err := http.Post(
		s.server.URL+"/api/v1/query/natural",
		"application/json",
		bytes.NewBuffer([]byte("invalid json")),
	)
	require.NoError(s.T(), err)
	defer resp.Body.Close()
	assert.Equal(s.T(), http.StatusBadRequest, resp.StatusCode)

	// 测试空的查询
	emptyQuery := api.NaturalQueryRequest{Query: ""}
	jsonBody, _ := json.Marshal(emptyQuery)

	resp, err = http.Post(
		s.server.URL+"/api/v1/query/natural",
		"application/json",
		bytes.NewBuffer(jsonBody),
	)
	require.NoError(s.T(), err)
	defer resp.Body.Close()
	assert.Equal(s.T(), http.StatusBadRequest, resp.StatusCode)

	// 测试不存在的端点
	resp, err = http.Get(s.server.URL + "/api/v1/nonexistent")
	require.NoError(s.T(), err)
	defer resp.Body.Close()
	assert.Equal(s.T(), http.StatusNotFound, resp.StatusCode)
}

// MockDatabase 实现storage.Database接口用于测试
type MockDatabase struct{}

func (m *MockDatabase) GetDB() interface{} {
	return &struct{}{}
}

func (m *MockDatabase) Close() error {
	return nil
}

// TestIntegrationSuite 运行集成测试套件
func TestIntegrationSuite(t *testing.T) {
	suite.Run(t, new(IntegrationTestSuite))
}

// TestMCPProtocolCompliance MCP协议兼容性测试
func TestMCPProtocolCompliance(t *testing.T) {
	// 这里可以添加MCP协议兼容性测试
	// 例如测试JSON-RPC 2.0消息格式
	t.Run("JSON-RPC 2.0 Message Format", func(t *testing.T) {
		// 测试请求消息格式
		request := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "initialize",
			"params": map[string]interface{}{
				"protocolVersion": "2025-06-18",
			},
		}

		data, err := json.Marshal(request)
		require.NoError(t, err)

		var parsed map[string]interface{}
		err = json.Unmarshal(data, &parsed)
		require.NoError(t, err)

		assert.Equal(t, "2.0", parsed["jsonrpc"])
		assert.Equal(t, float64(1), parsed["id"])
		assert.Equal(t, "initialize", parsed["method"])
	})
}

// BenchmarkAPIPerformance API性能基准测试
func BenchmarkAPIPerformance(b *testing.B) {
	// 设置测试环境
	gin.SetMode(gin.TestMode)
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)

	db := &MockDatabase{}
	mcpManager := mcp.NewManager(logger)
	defer mcpManager.Close()

	router := gin.New()
	apiHandler := api.NewHandler(logger, db, mcpManager)
	router.POST("/query", apiHandler.HandleNaturalQuery)

	server := httptest.NewServer(router)
	defer server.Close()

	queryBody := api.NaturalQueryRequest{
		Query: "benchmark query",
	}
	jsonBody, _ := json.Marshal(queryBody)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := http.Post(
			server.URL+"/query",
			"application/json",
			bytes.NewBuffer(jsonBody),
		)
		if err != nil {
			b.Fatal(err)
		}
		resp.Body.Close()
	}
}