package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/mcpsoc/mcpsoc/internal/mcp"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockDatabase 模拟数据库接口
type MockDatabase struct {
	mock.Mock
}

func (m *MockDatabase) GetDB() interface{} {
	args := m.Called()
	return args.Get(0)
}

func (m *MockDatabase) Close() error {
	args := m.Called()
	return args.Error(0)
}

// MockMCPManager 模拟MCP管理器
type MockMCPManager struct {
	mock.Mock
}

func (m *MockMCPManager) ListServers() []mcp.ServerStatus {
	args := m.Called()
	return args.Get(0).([]mcp.ServerStatus)
}

func (m *MockMCPManager) GetServer(serverID string) (*mcp.Client, error) {
	args := m.Called(serverID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*mcp.Client), args.Error(1)
}

func (m *MockMCPManager) CallTool(serverID, toolName string, arguments map[string]interface{}) (*mcp.ToolResult, error) {
	args := m.Called(serverID, toolName, arguments)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*mcp.ToolResult), args.Error(1)
}

func setupTestHandler() (*Handler, *MockDatabase, *MockMCPManager) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // 减少测试输出

	mockDB := &MockDatabase{}
	mockMCPManager := &MockMCPManager{}

	handler := NewHandler(logger, mockDB, mockMCPManager)
	return handler, mockDB, mockMCPManager
}

func TestNewHandler(t *testing.T) {
	handler, _, _ := setupTestHandler()
	
	assert.NotNil(t, handler)
	assert.NotNil(t, handler.logger)
	assert.NotNil(t, handler.db)
	assert.NotNil(t, handler.mcpManager)
}

func TestHandleNaturalQuery_Success(t *testing.T) {
	handler, mockDB, _ := setupTestHandler()

	// 设置测试路由
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/query", handler.HandleNaturalQuery)

	// 准备请求数据
	requestBody := NaturalQueryRequest{
		Query:     "查找过去24小时内的高危威胁事件",
		Context:   map[string]interface{}{"time_range": "24h"},
		SessionID: "test-session-123",
	}
	jsonBody, _ := json.Marshal(requestBody)

	// 模拟数据库调用
	mockDB.On("GetDB").Return(&struct{}{})

	// 发送请求
	req, _ := http.NewRequest("POST", "/query", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// 验证响应
	assert.Equal(t, http.StatusOK, w.Code)

	var response NaturalQueryResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "completed", response.Status)
	assert.NotEmpty(t, response.QueryID)
	assert.NotNil(t, response.Result)
	assert.Greater(t, response.ExecutionTime, 0.0)
}

func TestHandleNaturalQuery_InvalidRequest(t *testing.T) {
	handler, _, _ := setupTestHandler()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/query", handler.HandleNaturalQuery)

	// 发送无效的JSON
	req, _ := http.NewRequest("POST", "/query", bytes.NewBuffer([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleNaturalQuery_EmptyQuery(t *testing.T) {
	handler, _, _ := setupTestHandler()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/query", handler.HandleNaturalQuery)

	// 发送空查询
	requestBody := NaturalQueryRequest{
		Query: "",
	}
	jsonBody, _ := json.Marshal(requestBody)

	req, _ := http.NewRequest("POST", "/query", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleStructuredQuery_Success(t *testing.T) {
	handler, mockDB, _ := setupTestHandler()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/structured", handler.HandleStructuredQuery)

	requestBody := StructuredQueryRequest{
		DataSource: "security_events",
		Filters: map[string]interface{}{
			"severity": "high",
		},
		Limit:  10,
		Offset: 0,
	}
	jsonBody, _ := json.Marshal(requestBody)

	// 模拟数据库调用
	mockDB.On("GetDB").Return(&struct{}{})

	req, _ := http.NewRequest("POST", "/structured", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response StructuredQueryResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.GreaterOrEqual(t, response.TotalCount, int64(0))
	assert.NotNil(t, response.Data)
	assert.Greater(t, response.ExecutionTime, 0.0)
}

func TestListMCPServers_Success(t *testing.T) {
	handler, _, mockMCPManager := setupTestHandler()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/servers", handler.ListMCPServers)

	// 模拟MCP服务器列表
	expectedServers := []mcp.ServerStatus{
		{
			ID:     "firewall-01",
			Name:   "pfSense Firewall",
			Type:   "firewall",
			Status: "connected",
		},
		{
			ID:     "waf-01",
			Name:   "ModSecurity WAF",
			Type:   "waf",
			Status: "connected",
		},
	}
	mockMCPManager.On("ListServers").Return(expectedServers)

	req, _ := http.NewRequest("GET", "/servers", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	servers := response["servers"].([]interface{})
	assert.Len(t, servers, 2)

	mockMCPManager.AssertExpectations(t)
}

func TestGetMCPServer_Success(t *testing.T) {
	handler, _, mockMCPManager := setupTestHandler()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/servers/:id", handler.GetMCPServer)

	// 模拟获取服务器
	expectedServers := []mcp.ServerStatus{
		{
			ID:     "firewall-01",
			Name:   "pfSense Firewall",
			Type:   "firewall",
			Status: "connected",
		},
	}
	mockMCPManager.On("ListServers").Return(expectedServers)

	req, _ := http.NewRequest("GET", "/servers/firewall-01", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	mockMCPManager.AssertExpectations(t)
}

func TestGetMCPServer_NotFound(t *testing.T) {
	handler, _, mockMCPManager := setupTestHandler()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/servers/:id", handler.GetMCPServer)

	// 返回空的服务器列表
	mockMCPManager.On("ListServers").Return([]mcp.ServerStatus{})

	req, _ := http.NewRequest("GET", "/servers/nonexistent", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)

	mockMCPManager.AssertExpectations(t)
}

func TestCallMCPTool_Success(t *testing.T) {
	handler, _, mockMCPManager := setupTestHandler()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/servers/:id/tools/:tool", handler.CallMCPTool)

	// 模拟工具调用结果
	expectedResult := &mcp.ToolResult{
		Content: []mcp.Content{
			{
				Type: "text",
				Text: "Tool executed successfully",
			},
		},
		IsError: false,
	}

	arguments := map[string]interface{}{
		"param1": "value1",
		"param2": "value2",
	}

	mockMCPManager.On("CallTool", "firewall-01", "get_logs", arguments).Return(expectedResult, nil)

	// 准备请求体
	requestBody := map[string]interface{}{
		"arguments": arguments,
	}
	jsonBody, _ := json.Marshal(requestBody)

	req, _ := http.NewRequest("POST", "/servers/firewall-01/tools/get_logs", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "success", response["status"])
	assert.NotNil(t, response["result"])

	mockMCPManager.AssertExpectations(t)
}

// Benchmark tests
func BenchmarkHandleNaturalQuery(b *testing.B) {
	handler, mockDB, _ := setupTestHandler()
	
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/query", handler.HandleNaturalQuery)

	requestBody := NaturalQueryRequest{
		Query:   "test query",
		Context: map[string]interface{}{},
	}
	jsonBody, _ := json.Marshal(requestBody)

	mockDB.On("GetDB").Return(&struct{}{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("POST", "/query", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}

// Helper functions for testing
func generateQueryID() string {
	return "test-query-id-123"
}