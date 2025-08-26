package ai

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAIServiceIntegration(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// 创建AI服务配置
	config := &Config{
		DefaultProvider: "mock",
		Providers: []ProviderConfig{
			{
				Name:   "mock",
				Type:   ProviderOpenAI,
				APIKey: "test-key",
				Model:  "gpt-3.5-turbo",
			},
		},
	}

	// 创建AI服务
	service, err := NewService(logger, config)
	require.NoError(t, err)
	defer service.Close()

	t.Run("TestQueryParser", func(t *testing.T) {
		parser := NewQueryParser(service, logger)
		
		// 模拟可用工具
		tools := []AvailableTool{
			{
				Name:        "get_firewall_logs",
				Description: "获取防火墙日志",
				Server:      "firewall-server",
				Parameters: []ToolParameter{
					{Name: "time_range", Type: "string", Required: false},
					{Name: "limit", Type: "integer", Required: false},
				},
			},
		}

		// 测试自然语言查询解析
		query := "查找过去24小时内的防火墙日志"
		
		// 使用规则解析（不依赖真实AI服务）
		parsed, err := parser.parseWithRules(query, tools, nil, "log_analysis")
		require.NoError(t, err)
		
		assert.Equal(t, "log_analysis", parsed.Intent)
		assert.True(t, parsed.Confidence > 0)
		assert.Len(t, parsed.ToolCalls, 1)
		assert.Equal(t, "get_firewall_logs", parsed.ToolCalls[0].Tool)
	})

	t.Run("TestPromptManager", func(t *testing.T) {
		manager := NewPromptManager()
		
		// 测试模板注册
		template := &PromptTemplate{
			ID:          "test_template",
			Name:        "测试模板",
			Description: "用于测试的模板",
			Category:    "test",
			Template:    "Hello {{.Name}}, welcome to {{.System}}!",
			Variables: []TemplateVar{
				{Name: "Name", Type: "string", Required: true},
				{Name: "System", Type: "string", Required: true},
			},
		}
		
		err := manager.RegisterTemplate(template)
		require.NoError(t, err)
		
		// 测试模板渲染
		data := map[string]interface{}{
			"Name":   "Alice",
			"System": "MCPSoc",
		}
		
		rendered, err := manager.RenderPrompt("test_template", data)
		require.NoError(t, err)
		assert.Equal(t, "Hello Alice, welcome to MCPSoc!", rendered)
		
		// 测试获取默认模板
		templates := manager.GetTemplatesByCategory("threat_analysis")
		assert.True(t, len(templates) > 0)
	})

	t.Run("TestToolTranslator", func(t *testing.T) {
		// 由于ToolTranslator需要真实的MCP管理器，这里只测试基本结构
		translator := &ToolTranslator{
			logger: logger,
		}
		
		// 测试辅助函数
		assert.True(t, translator.isCriticalTool("get_firewall_logs"))
		assert.False(t, translator.isCriticalTool("non_critical_tool"))
		
		// 测试工具分类
		category := translator.getToolCategory("get_firewall_logs")
		assert.Equal(t, "network_security", category)
		
		category = translator.getToolCategory("unknown_tool")
		assert.Equal(t, "general", category)
	})
}

func TestQueryIntentClassification(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	config := &Config{
		DefaultProvider: "mock",
		Providers:       []ProviderConfig{},
	}

	service, err := NewService(logger, config)
	require.NoError(t, err)
	defer service.Close()

	parser := NewQueryParser(service, logger)

	testCases := []struct {
		query          string
		expectedIntent string
	}{
		{"查找威胁信息", "threat_analysis"},
		{"分析安全事件", "incident_response"},
		{"查看系统日志", "log_analysis"},
		{"检查漏洞", "vulnerability_assessment"},
		{"监控系统状态", "monitoring"},
		{"调查安全事件", "forensics"},
		{"一般查询", "general"},
	}

	for _, tc := range testCases {
		t.Run(tc.query, func(t *testing.T) {
			intent := parser.classifyIntent(tc.query)
			assert.Equal(t, tc.expectedIntent, intent)
		})
	}
}

func TestTimeRangeExtraction(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	config := &Config{
		DefaultProvider: "mock",
		Providers:       []ProviderConfig{},
	}

	service, err := NewService(logger, config)
	require.NoError(t, err)
	defer service.Close()

	parser := NewQueryParser(service, logger)

	testCases := []struct {
		query          string
		expectedPeriod string
	}{
		{"查找过去1小时的日志", "1h"},
		{"查找最近24小时的事件", "24h"},
		{"查找过去7天的威胁", "7d"},
		{"查找最近30天的数据", "30d"},
		{"查找过去2小时的信息", "2h"},
	}

	for _, tc := range testCases {
		t.Run(tc.query, func(t *testing.T) {
			timeRange := parser.extractTimeRange(tc.query)
			if tc.expectedPeriod != "" {
				require.NotNil(t, timeRange)
				assert.Equal(t, tc.expectedPeriod, timeRange.Period)
				assert.True(t, time.Since(timeRange.Start) > 0)
			} else {
				assert.Nil(t, timeRange)
			}
		})
	}
}

func TestQueryNormalization(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	config := &Config{
		DefaultProvider: "mock",
		Providers:       []ProviderConfig{},
	}

	service, err := NewService(logger, config)
	require.NoError(t, err)
	defer service.Close()

	parser := NewQueryParser(service, logger)

	testCases := []struct {
		input    string
		expected string
	}{
		{"查找最近一小时的日志", "查找1h的日志"},
		{"过去24小时的威胁事件", "24h的威胁事件"},
		{"最近一周的安全数据", "7d的安全数据"},
		{"过去一个月的统计", "30d的统计"},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			normalized := parser.normalizeQuery(tc.input)
			assert.Equal(t, tc.expected, normalized)
		})
	}
}

func BenchmarkQueryParsing(b *testing.B) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	config := &Config{
		DefaultProvider: "mock",
		Providers:       []ProviderConfig{},
	}

	service, _ := NewService(logger, config)
	defer service.Close()

	parser := NewQueryParser(service, logger)
	tools := []AvailableTool{
		{
			Name:        "get_firewall_logs",
			Description: "获取防火墙日志",
			Server:      "firewall-server",
		},
	}

	query := "查找过去24小时内的高危威胁事件"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parser.parseWithRules(query, tools, nil, "threat_analysis")
	}
}