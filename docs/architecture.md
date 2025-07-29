# MCPSoc 架构设计文档

## 1. 整体架构概述

MCPSoc采用基于MCP协议的开放式、分层架构，实现AI驱动的智能安全运营。系统通过标准化的MCP接口，将各种安全工具封装为MCP Server，由中央MCP Host进行统一编排和管理。

## 2. 架构原则

### 2.1 开放性原则
- 基于MCP开放协议，任何符合MCP标准的安全工具都可以接入
- 支持多厂商、多类型安全工具的统一管理
- 避免厂商锁定，保障客户投资

### 2.2 模块化原则
- 各组件松耦合设计，可独立部署和扩展
- 支持微服务架构，便于运维和管理
- 组件间通过标准接口通信

### 2.3 标准化原则
- 统一的数据格式和API接口
- 基于JSON-RPC 2.0的通信协议
- 标准化的错误处理和日志格式

### 2.4 智能化原则
- AI驱动的威胁检测和分析
- 自然语言交互界面
- 自动化响应和编排

## 3. 系统分层架构

```
┌─────────────────────────────────────────────────────────┐
│                   Presentation Layer                   │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────────┐    │
│  │   Web UI    │ │  Mobile App │ │   API Gateway   │    │
│  └─────────────┘ └─────────────┘ └─────────────────┘    │
└─────────────────────────────────────────────────────────┘
                             │
┌─────────────────────────────────────────────────────────┐
│                  Application Layer                     │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────────┐    │
│  │ MCP Host    │ │ MCPSoc      │ │ Workflow        │    │
│  │ Service     │ │ Agent       │ │ Engine          │    │
│  └─────────────┘ └─────────────┘ └─────────────────┘    │
└─────────────────────────────────────────────────────────┘
                             │
┌─────────────────────────────────────────────────────────┐
│                Integration Layer                       │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────────┐    │
│  │ MCP Client  │ │ Message     │ │ Protocol        │    │
│  │ Manager     │ │ Router      │ │ Adapter         │    │
│  └─────────────┘ └─────────────┘ └─────────────────┘    │
└─────────────────────────────────────────────────────────┘
                             │
┌─────────────────────────────────────────────────────────┐
│                    MCP Server Layer                    │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────┐  │
│  │Firewall  │ │   WAF    │ │    AV    │ │  Threat   │  │
│  │Server    │ │ Server   │ │ Server   │ │  Intel    │  │
│  └──────────┘ └──────────┘ └──────────┘ │  Server   │  │
│                                         └───────────┘  │
└─────────────────────────────────────────────────────────┘
                             │
┌─────────────────────────────────────────────────────────┐
│                     Data Layer                         │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────────┐    │
│  │ TimescaleDB │ │  ArangoDB   │ │    Redis        │    │
│  │(时序数据)    │ │  (图数据)    │ │   (缓存)         │    │
│  └─────────────┘ └─────────────┘ └─────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

## 4. 核心组件详细设计

### 4.1 MCP Host 服务

**职责**:
- 接收和处理用户查询请求
- 任务分解和执行计划生成
- 跨域数据关联和综合分析
- 工作流编排和自动化响应

**技术实现**:
```go
type MCPHost struct {
    clientManager *MCPClientManager
    agentService  *AgentService
    workflowEngine *WorkflowEngine
    queryProcessor *QueryProcessor
}

type QueryRequest struct {
    Query     string            `json:"query"`
    Context   map[string]interface{} `json:"context"`
    UserID    string            `json:"user_id"`
    SessionID string            `json:"session_id"`
}

type QueryResponse struct {
    Result    interface{}       `json:"result"`
    Insights  []Insight         `json:"insights"`
    Actions   []RecommendedAction `json:"actions"`
    Evidence  []Evidence        `json:"evidence"`
}
```

**核心功能模块**:
- **自然语言处理**: 意图识别和实体提取
- **任务规划**: 查询分解和执行计划生成
- **数据融合**: 多源数据关联和聚合
- **结果生成**: 智能报告和可视化

### 4.2 MCPSoc Agent (AI引擎)

**职责**:
- 提供大模型推理和决策能力
- 威胁检测和安全分析
- 知识库管理和检索
- 持续学习和模型优化

**技术架构**:
```go
type MCPSocAgent struct {
    llmProvider   LLMProvider
    vectorDB      VectorDatabase
    knowledgeBase *SecurityKnowledgeBase
    reasoningEngine *ReasoningEngine
}

type LLMProvider interface {
    GenerateCompletion(prompt string, context Context) (*Completion, error)
    GenerateEmbedding(text string) ([]float64, error)
    AnalyzeThreat(indicators []IOC) (*ThreatAnalysis, error)
}
```

**支持的AI模型**:
- OpenAI GPT-4/GPT-3.5
- Anthropic Claude
- 本地部署模型 (Llama2、ChatGLM等)
- 定制化安全领域模型

### 4.3 MCP Client 管理器

**职责**:
- 维护与各MCP Server的连接
- 协议转换和消息路由
- 连接状态监控和故障恢复
- 负载均衡和请求分发

**连接管理**:
```go
type MCPClientManager struct {
    clients    map[string]*MCPClient
    registry   *ServerRegistry
    loadBalancer *LoadBalancer
    healthChecker *HealthChecker
}

type MCPClient struct {
    serverID    string
    connection  net.Conn
    transport   Transport
    capabilities ServerCapabilities
    status      ConnectionStatus
}
```

### 4.4 MCP Server 框架

**设计目标**:
提供统一的MCP Server开发框架，简化安全工具的MCP化改造。

**框架特性**:
- 多语言SDK支持
- 标准化配置和部署
- 内置认证和授权
- 自动化文档生成

**SDK接口示例**:
```go
type MCPServer interface {
    GetCapabilities() Capabilities
    GetTools() []Tool
    GetResources() []Resource
    GetPrompts() []Prompt
    CallTool(name string, args map[string]interface{}) (*ToolResult, error)
    GetResource(uri string) (*ResourceContent, error)
}

type Tool struct {
    Name        string      `json:"name"`
    Description string      `json:"description"`
    InputSchema JSONSchema  `json:"inputSchema"`
    Handler     ToolHandler `json:"-"`
}
```

## 5. 数据源接入层设计

### 5.1 防火墙数据接入

**支持的防火墙类型**:
- pfSense/OPNsense
- FortiGate
- Palo Alto Networks
- 开源防火墙 (iptables、ufw)

**数据接入方式**:
- Syslog日志收集
- SNMP监控数据
- REST API调用
- 配置文件解析

**标准化数据模型**:
```json
{
  "timestamp": "2025-07-29T15:19:59Z",
  "source": "pfsense-fw-01",
  "event_type": "firewall_log",
  "action": "block",
  "src_ip": "192.168.1.100",
  "dst_ip": "10.0.0.1",
  "src_port": 12345,
  "dst_port": 80,
  "protocol": "tcp",
  "interface": "wan",
  "rule_id": "block_external_access",
  "severity": "medium",
  "classification": "policy_violation"
}
```

### 5.2 WAF数据接入

**支持的WAF类型**:
- ModSecurity
- AWS WAF
- Cloudflare WAF
- NGINX ModSecurity

**数据处理功能**:
- 攻击事件检测和分类
- 规则匹配结果分析
- 性能监控和优化建议
- 误报分析和调优

### 5.3 威胁情报接入

**支持的情报格式**:
- STIX/TAXII 2.0
- MISP
- JSON威胁情报
- CSV/XML格式

**情报处理流程**:
1. 数据收集和验证
2. 格式标准化转换
3. 去重和质量评估
4. 本地缓存和索引
5. 实时更新和分发

## 6. 数据存储架构

### 6.1 时序数据存储 (TimescaleDB)

**用途**: 存储安全事件、日志、指标等时序数据

**表结构设计**:
```sql
CREATE TABLE security_events (
    id BIGSERIAL,
    timestamp TIMESTAMPTZ NOT NULL,
    source_type VARCHAR(50) NOT NULL,
    source_id VARCHAR(100) NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    severity INTEGER NOT NULL,
    raw_data JSONB,
    processed_data JSONB,
    tags TEXT[],
    PRIMARY KEY (id, timestamp)
);

SELECT create_hypertable('security_events', 'timestamp');
```

### 6.2 图数据存储 (ArangoDB)

**用途**: 存储安全实体关系、攻击路径、依赖关系等图数据

**图模型设计**:
- **节点类型**: 用户、设备、IP地址、域名、文件、进程
- **边类型**: 访问、通信、执行、包含、依赖

### 6.3 缓存层 (Redis)

**用途**: 
- 会话管理
- 查询结果缓存
- 实时计数器
- 分布式锁

## 7. 安全设计

### 7.1 认证和授权

**认证方式**:
- JWT Token认证
- OAuth 2.0集成
- LDAP/AD集成
- 多因素认证(MFA)

**权限模型**:
- 基于角色的访问控制(RBAC)
- 细粒度权限控制
- 数据源级别权限
- API接口权限

### 7.2 数据保护

**传输安全**:
- TLS 1.3加密
- 证书管理
- 密钥轮换

**存储安全**:
- 数据库加密
- 敏感数据脱敏
- 访问审计日志

### 7.3 网络安全

**网络隔离**:
- VPC网络隔离
- 防火墙规则
- 网络访问控制

**API安全**:
- 速率限制
- 输入验证
- SQL注入防护
- XSS防护

## 8. 部署架构

### 8.1 单机部署

适用于小规模环境和测试场景：

```yaml
version: '3.8'
services:
  mcpsoc-host:
    image: mcpsoc/host:latest
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=postgresql://user:pass@db:5432/mcpsoc
      - REDIS_URL=redis://redis:6379
  
  postgres:
    image: timescale/timescaledb:latest-pg14
    environment:
      - POSTGRES_DB=mcpsoc
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=pass
  
  redis:
    image: redis:7-alpine
```

### 8.2 集群部署

适用于生产环境和大规模部署：

```yaml
# Kubernetes部署示例
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcpsoc-host
spec:
  replicas: 3
  selector:
    matchLabels:
      app: mcpsoc-host
  template:
    metadata:
      labels:
        app: mcpsoc-host
    spec:
      containers:
      - name: mcpsoc-host
        image: mcpsoc/host:latest
        ports:
        - containerPort: 8080
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: mcpsoc-secrets
              key: database-url
```

### 8.3 云原生部署

支持主流云平台：
- AWS (EKS, RDS, ElastiCache)
- Azure (AKS, Azure Database)
- Google Cloud (GKE, Cloud SQL)
- 私有云 (OpenStack, VMware)

## 9. 监控和运维

### 9.1 监控指标

**系统指标**:
- CPU、内存、磁盘使用率
- 网络流量和延迟
- 服务可用性

**业务指标**:
- 查询响应时间
- MCP Server连接状态
- 威胁检测准确率
- 误报率

### 9.2 日志管理

**日志类型**:
- 系统运行日志
- 用户操作日志
- 安全事件日志
- API访问日志

**日志格式**:
```json
{
  "timestamp": "2025-07-29T15:19:59Z",
  "level": "info",
  "service": "mcpsoc-host",
  "component": "query-processor",
  "message": "Query processed successfully",
  "user_id": "user123",
  "session_id": "session456",
  "query_id": "query789",
  "duration_ms": 1500
}
```

### 9.3 性能优化

**缓存策略**:
- 查询结果缓存
- 静态资源缓存
- 数据库查询缓存

**负载均衡**:
- MCP Server负载均衡
- API网关负载均衡
- 数据库读写分离

## 10. 扩展性设计

### 10.1 水平扩展

- 无状态服务设计
- 数据库分片
- 消息队列解耦
- 微服务架构

### 10.2 插件机制

- MCP Server插件框架
- 自定义分析插件
- 第三方集成插件
- UI扩展插件

### 10.3 API扩展

- RESTful API
- GraphQL API
- WebSocket实时接口
- 开发者SDK

这份架构设计文档为MCPSoc项目提供了全面的技术指导，确保系统的可扩展性、安全性和高性能。