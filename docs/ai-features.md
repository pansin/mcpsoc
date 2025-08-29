# MCPSoc AI功能说明

## 🤖 AI驱动的智能安全运营

MCPSoc集成了先进的AI服务，提供智能化的安全运营能力，包括自然语言查询、威胁分析、事件响应等功能。

## 🌟 核心AI功能

### 1. 自然语言查询解析器 (Natural Language Query Parser)

支持将自然语言查询转换为具体的MCP工具调用，让安全分析师可以用自然语言与系统交互。

**特性：**
- 🗣️ **意图识别**：自动识别查询意图（威胁分析、日志分析、事件响应等）
- ⏰ **时间范围提取**：智能提取查询中的时间信息
- 🔧 **工具映射**：将查询转换为对应的MCP工具调用
- 🎯 **参数推理**：根据上下文推理工具调用参数

**支持的查询类型：**
- `threat_analysis` - 威胁分析
- `incident_response` - 事件响应
- `log_analysis` - 日志分析
- `vulnerability_assessment` - 漏洞评估
- `monitoring` - 系统监控
- `forensics` - 安全取证
- `general` - 一般查询

**示例查询：**
```bash
# 威胁分析
"分析过去24小时内的安全威胁"
"查找可疑的IP地址活动"

# 日志分析
"查看防火墙日志中的异常连接"
"分析Web访问日志的攻击模式"

# 事件响应
"为恶意软件感染生成响应计划"
"制定数据泄露的应急措施"
```

### 2. 提示词模板管理系统 (Prompt Template Manager)

提供可复用的AI提示词模板，确保AI分析的一致性和专业性。

**内置模板：**
- **威胁分析模板** (`threat_analysis_basic`): 结构化威胁评估
- **事件响应模板** (`incident_response_plan`): 详细响应计划生成
- **查询转换模板** (`nl_to_mcp_query`): 自然语言到MCP调用转换
- **日志分析模板** (`log_analysis`): 安全日志分析
- **漏洞评估模板** (`vulnerability_assessment`): 漏洞风险评估

**模板变量支持：**
```go
// 模板变量定义
type TemplateVar struct {
    Name        string `json:"name"`
    Type        string `json:"type"`        // string, integer, array, map
    Description string `json:"description"`
    Required    bool   `json:"required"`
    Default     string `json:"default"`
}
```

### 3. 智能工具调用转换器 (Tool Translator)

将解析后的查询转换为具体的MCP工具调用，并智能编排执行计划。

**执行策略：**
- **并行执行**：独立的工具调用并行执行以提高效率
- **串行执行**：有依赖关系的工具按顺序执行
- **错误处理**：智能处理工具调用失败，提供降级方案
- **结果聚合**：将多个工具的结果聚合成统一的分析报告

**结果分析：**
```go
type AggregatedResult struct {
    Query           string            `json:"query"`
    Intent          string            `json:"intent"`
    TotalDuration   time.Duration     `json:"total_duration"`
    SuccessCount    int               `json:"success_count"`
    ErrorCount      int               `json:"error_count"`
    Results         []ExecutionResult `json:"results"`
    Summary         interface{}       `json:"summary"`
    Recommendations []string          `json:"recommendations"`
}
```

### 4. AI提供商支持 (AI Providers)

支持多种AI服务提供商，可以根据需求选择最适合的AI模型。

**支持的提供商：**
- **OpenAI**: GPT-3.5/GPT-4 系列模型
- **Anthropic**: Claude 3 系列模型
- **本地模型**: 支持Ollama等本地部署的开源模型

**配置示例：**
```go
aiConfig := &ai.Config{
    DefaultProvider: "openai",
    Providers: []ai.ProviderConfig{
        {
            Name:    "openai",
            Type:    ai.ProviderOpenAI,
            APIKey:  os.Getenv("OPENAI_API_KEY"),
            Model:   "gpt-3.5-turbo",
            BaseURL: "https://api.openai.com/v1",
        },
        {
            Name:    "claude",
            Type:    ai.ProviderAnthropic,
            APIKey:  os.Getenv("ANTHROPIC_API_KEY"),
            Model:   "claude-3-haiku-20240307",
        },
    },
}
```

## 🚀 使用方法

### 1. 环境配置

设置AI服务的API密钥：

```bash
# OpenAI API密钥
export OPENAI_API_KEY="your-openai-api-key"

# Anthropic API密钥（可选）
export ANTHROPIC_API_KEY="your-anthropic-api-key"
```

### 2. 启动服务

```bash
# 启动MCPSoc Host服务
./bin/mcpsoc-host --config config/config.yaml

# 或使用Docker
docker-compose up mcpsoc-host
```

### 3. API调用示例

#### 自然语言查询
```bash
curl -X POST http://localhost:8080/api/v1/query/natural \
  -H "Content-Type: application/json" \
  -d '{
    "query": "分析过去24小时内的安全威胁",
    "context": {
      "time_range": "24h",
      "severity": "high"
    },
    "session_id": "user-session-001"
  }'
```

#### 响应格式
```json
{
  "query_id": "query-abc123",
  "status": "completed",
  "result": {
    "intent": "threat_analysis",
    "total_duration": "2.34s",
    "success_count": 3,
    "error_count": 0,
    "summary": {
      "threat_summary": {
        "total_threats_detected": 15,
        "high_severity_threats": 3,
        "threat_level": "medium"
      }
    },
    "recommendations": [
      "建议加强对高危IP的监控",
      "考虑更新威胁情报源"
    ]
  },
  "insights": [
    {
      "type": "threat_analysis",
      "severity": "high",
      "message": "检测到3个高危威胁事件",
      "confidence": 0.85
    }
  ],
  "actions": [
    {
      "action": "block_ip",
      "target": "192.168.1.100",
      "reason": "多次恶意连接尝试",
      "priority": "high"
    }
  ],
  "execution_time": 2.34
}
```

### 4. 演示脚本

运行AI功能演示：

```bash
# 运行AI功能演示脚本
./scripts/demo-ai.sh
```

## 🔧 自定义开发

### 添加新的提示词模板

```go
// 注册自定义模板
template := &ai.PromptTemplate{
    ID:          "custom_analysis",
    Name:        "自定义分析模板",
    Description: "用于特定场景的分析模板",
    Category:    "custom",
    Template:    "分析以下数据：{{.Data}}...",
    Variables: []ai.TemplateVar{
        {Name: "Data", Type: "string", Required: true},
    },
}

promptManager.RegisterTemplate(template)
```

### 扩展查询意图

在`parser.go`中添加新的意图类型：

```go
// 在classifyIntent函数中添加新的意图模式
intentPatterns["custom_intent"] = []string{
    "custom", "特定关键词", "specific keywords",
}
```

### 添加新的AI提供商

实现`Provider`接口：

```go
type CustomProvider struct {
    // 实现Provider接口的所有方法
}

func (p *CustomProvider) Query(ctx context.Context, req *QueryRequest) (*QueryResponse, error) {
    // 自定义AI服务调用逻辑
}
```

## 📊 性能优化

### 缓存策略
- AI响应缓存：相似查询的结果会被缓存
- 提示词模板缓存：预编译的模板减少渲染时间
- 工具调用结果缓存：避免重复的工具调用

### 并发控制
- 智能并行执行：独立的工具调用并行处理
- 限流保护：防止API调用频率过高
- 超时控制：避免长时间等待AI响应

### 监控指标
- 查询响应时间
- AI服务可用性
- 工具调用成功率
- 缓存命中率

## 🔐 安全考虑

### API密钥管理
- 使用环境变量存储API密钥
- 支持密钥轮换
- 日志中脱敏处理

### 数据隐私
- AI查询数据的本地处理选项
- 敏感信息过滤
- 查询历史的安全存储

### 访问控制
- API访问权限控制
- 会话管理和验证
- 审计日志记录

## 🐛 故障排除

### 常见问题

1. **AI服务无法连接**
   ```
   检查API密钥是否正确设置
   验证网络连接和API服务状态
   查看日志中的详细错误信息
   ```

2. **查询解析失败**
   ```
   检查查询语言是否支持
   验证MCP服务器连接状态
   查看可用工具列表
   ```

3. **响应时间过长**
   ```
   检查AI模型选择是否合适
   优化查询参数和上下文
   启用缓存机制
   ```

### 调试模式

启用调试日志：

```bash
export LOG_LEVEL=debug
export MCP_DEBUG=true
./bin/mcpsoc-host
```

## 📚 相关文档

- [MCP协议规范](https://spec.modelcontextprotocol.io/)
- [OpenAI API文档](https://platform.openai.com/docs)
- [Anthropic Claude API](https://docs.anthropic.com/)
- [MCPSoc架构设计](./docs/architecture.md)
- [API接口文档](./docs/api.md)