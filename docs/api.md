# MCPSoc API 文档

## 概述

MCPSoc提供RESTful API接口，支持安全运营中心的各种功能调用。所有API均基于HTTP协议，使用JSON格式进行数据交换。

## 基础信息

- **Base URL**: `https://api.mcpsoc.org/v1`
- **协议**: HTTPS
- **数据格式**: JSON
- **认证方式**: Bearer Token (JWT)
- **API版本**: v1

## 认证

所有API请求都需要在Header中包含认证Token：

```http
Authorization: Bearer <your-jwt-token>
Content-Type: application/json
```

### 获取认证Token

```http
POST /auth/login
```

**请求体**:
```json
{
  "username": "your-username",
  "password": "your-password"
}
```

**响应**:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 3600,
  "user_info": {
    "id": "user123",
    "username": "analyst1",
    "role": "security_analyst",
    "permissions": ["query", "analyze", "respond"]
  }
}
```

## 核心API

### 1. 安全查询API

#### 1.1 自然语言查询

```http
POST /query/natural
```

**描述**: 使用自然语言进行安全查询和分析

**请求体**:
```json
{
  "query": "查找过去24小时内来自可疑IP的所有连接",
  "context": {
    "time_range": "24h",
    "severity": "medium",
    "data_sources": ["firewall", "ids"]
  },
  "session_id": "session-123"
}
```

**响应**:
```json
{
  "query_id": "query-456",
  "status": "completed",
  "result": {
    "summary": "发现15个来自可疑IP的连接",
    "insights": [
      {
        "type": "threat_indicator",
        "severity": "high",
        "message": "检测到来自已知恶意IP 192.168.1.100的多次连接尝试",
        "confidence": 0.95
      }
    ],
    "data": [
      {
        "timestamp": "2025-07-29T15:19:59Z",
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.5",
        "dst_port": 22,
        "protocol": "tcp",
        "action": "blocked",
        "threat_level": "high"
      }
    ]
  },
  "recommendations": [
    {
      "action": "block_ip",
      "target": "192.168.1.100",
      "reason": "多次恶意连接尝试",
      "priority": "high"
    }
  ],
  "execution_time": 2.5
}
```

#### 1.2 结构化查询

```http
POST /query/structured
```

**请求体**:
```json
{
  "data_source": "firewall",
  "filters": {
    "src_ip": "192.168.1.100",
    "time_range": {
      "start": "2025-07-29T00:00:00Z",
      "end": "2025-07-29T23:59:59Z"
    },
    "action": ["block", "deny"]
  },
  "aggregation": {
    "group_by": ["dst_port"],
    "count": true
  },
  "limit": 100
}
```

**响应**:
```json
{
  "total_count": 156,
  "aggregations": {
    "by_dst_port": {
      "22": 45,
      "80": 32,
      "443": 28,
      "3389": 51
    }
  },
  "data": [
    {
      "timestamp": "2025-07-29T15:19:59Z",
      "src_ip": "192.168.1.100",
      "dst_ip": "10.0.0.5",
      "dst_port": 22,
      "protocol": "tcp",
      "action": "blocked"
    }
  ]
}
```

### 2. MCP服务管理API

#### 2.1 获取MCP服务列表

```http
GET /mcp/servers
```

**响应**:
```json
{
  "servers": [
    {
      "id": "firewall-pfsense-01",
      "name": "pfSense Firewall",
      "type": "firewall",
      "status": "connected",
      "capabilities": {
        "tools": 8,
        "resources": 3,
        "prompts": 2
      },
      "last_heartbeat": "2025-07-29T15:18:30Z",
      "version": "1.0.0"
    },
    {
      "id": "waf-modsecurity-01",
      "name": "ModSecurity WAF",
      "type": "waf",
      "status": "connected",
      "capabilities": {
        "tools": 5,
        "resources": 2,
        "prompts": 1
      },
      "last_heartbeat": "2025-07-29T15:18:45Z",
      "version": "1.0.0"
    }
  ],
  "total": 2,
  "healthy": 2,
  "unhealthy": 0
}
```

#### 2.2 获取MCP服务详情

```http
GET /mcp/servers/{server_id}
```

**响应**:
```json
{
  "id": "firewall-pfsense-01",
  "name": "pfSense Firewall",
  "type": "firewall",
  "status": "connected",
  "endpoint": "tcp://192.168.1.1:8080",
  "capabilities": {
    "tools": [
      {
        "name": "block_ip",
        "description": "阻止指定IP地址的访问",
        "input_schema": {
          "type": "object",
          "properties": {
            "ip_address": {"type": "string"},
            "duration": {"type": "integer", "default": 3600}
          },
          "required": ["ip_address"]
        }
      }
    ],
    "resources": [
      {
        "uri": "firewall://pfsense/logs",
        "name": "防火墙日志",
        "mime_type": "application/json"
      }
    ]
  },
  "metrics": {
    "uptime": 86400,
    "requests_total": 1247,
    "requests_success": 1231,
    "requests_failed": 16,
    "avg_response_time": 120
  }
}
```

#### 2.3 调用MCP工具

```http
POST /mcp/servers/{server_id}/tools/{tool_name}
```

**请求体**:
```json
{
  "arguments": {
    "ip_address": "192.168.1.100",
    "duration": 7200
  }
}
```

**响应**:
```json
{
  "execution_id": "exec-789",
  "status": "success",
  "result": {
    "blocked_ip": "192.168.1.100",
    "rule_id": "block_rule_001",
    "expires_at": "2025-07-29T17:19:59Z",
    "message": "IP地址已成功阻止"
  },
  "execution_time": 0.5
}
```

### 3. 威胁分析API

#### 3.1 威胁指标分析

```http
POST /analysis/indicators
```

**请求体**:
```json
{
  "indicators": [
    {
      "type": "ip",
      "value": "192.168.1.100"
    },
    {
      "type": "domain",
      "value": "malicious.com"
    },
    {
      "type": "hash",
      "value": "d41d8cd98f00b204e9800998ecf8427e"
    }
  ],
  "analysis_depth": "deep",
  "include_context": true
}
```

**响应**:
```json
{
  "analysis_id": "analysis-123",
  "results": [
    {
      "indicator": {
        "type": "ip",
        "value": "192.168.1.100"
      },
      "threat_level": "high",
      "confidence": 0.92,
      "categories": ["malware", "botnet"],
      "sources": [
        {
          "name": "threat_intel_feed_1",
          "last_seen": "2025-07-29T10:30:00Z",
          "context": "已知僵尸网络C&C服务器"
        }
      ],
      "related_indicators": [
        {
          "type": "domain",
          "value": "command.malicious.com",
          "relationship": "resolves_to"
        }
      ]
    }
  ],
  "summary": {
    "total_indicators": 3,
    "high_risk": 1,
    "medium_risk": 1,
    "low_risk": 1
  }
}
```

#### 3.2 安全事件关联分析

```http
POST /analysis/correlation
```

**请求体**:
```json
{
  "events": [
    {
      "id": "event-001",
      "type": "firewall_block",
      "timestamp": "2025-07-29T15:00:00Z",
      "src_ip": "192.168.1.100",
      "dst_ip": "10.0.0.5"
    },
    {
      "id": "event-002",
      "type": "failed_login",
      "timestamp": "2025-07-29T15:01:00Z",
      "src_ip": "192.168.1.100",
      "target_user": "admin"
    }
  ],
  "time_window": "5m",
  "correlation_rules": ["brute_force_detection", "lateral_movement"]
}
```

**响应**:
```json
{
  "correlation_id": "corr-456",
  "matches": [
    {
      "rule_name": "brute_force_detection",
      "confidence": 0.88,
      "description": "检测到暴力破解攻击模式",
      "events": ["event-001", "event-002"],
      "timeline": {
        "start": "2025-07-29T15:00:00Z",
        "end": "2025-07-29T15:01:00Z",
        "duration": "1m"
      },
      "risk_score": 85
    }
  ],
  "attack_chain": {
    "phases": [
      {
        "name": "reconnaissance",
        "events": ["event-001"],
        "description": "攻击者扫描目标系统"
      },
      {
        "name": "initial_access",
        "events": ["event-002"],
        "description": "攻击者尝试获取初始访问权限"
      }
    ],
    "kill_chain": "MITRE ATT&CK"
  }
}
```

### 4. 响应行动API

#### 4.1 创建响应计划

```http
POST /response/plans
```

**请求体**:
```json
{
  "incident_id": "incident-789",
  "threat_level": "high",
  "affected_assets": [
    "192.168.1.5",
    "web-server-01"
  ],
  "response_type": "automated",
  "actions": [
    {
      "type": "isolate_host",
      "target": "192.168.1.5",
      "priority": 1
    },
    {
      "type": "block_ip",
      "target": "192.168.1.100",
      "priority": 2
    },
    {
      "type": "notify_analyst",
      "target": "security-team",
      "priority": 3
    }
  ]
}
```

**响应**:
```json
{
  "plan_id": "plan-123",
  "status": "created",
  "actions": [
    {
      "action_id": "action-001",
      "type": "isolate_host",
      "target": "192.168.1.5",
      "status": "pending",
      "estimated_time": 30
    },
    {
      "action_id": "action-002",
      "type": "block_ip",
      "target": "192.168.1.100",
      "status": "pending",
      "estimated_time": 10
    }
  ],
  "total_estimated_time": 45
}
```

#### 4.2 执行响应计划

```http
POST /response/plans/{plan_id}/execute
```

**请求体**:
```json
{
  "execution_mode": "automatic",
  "confirm_actions": false
}
```

**响应**:
```json
{
  "execution_id": "exec-456",
  "status": "executing",
  "progress": {
    "completed": 0,
    "total": 3,
    "current_action": "isolate_host"
  },
  "start_time": "2025-07-29T15:20:00Z"
}
```

#### 4.3 获取执行状态

```http
GET /response/executions/{execution_id}
```

**响应**:
```json
{
  "execution_id": "exec-456",
  "plan_id": "plan-123",
  "status": "completed",
  "progress": {
    "completed": 3,
    "total": 3,
    "success": 3,
    "failed": 0
  },
  "actions": [
    {
      "action_id": "action-001",
      "type": "isolate_host",
      "target": "192.168.1.5",
      "status": "success",
      "start_time": "2025-07-29T15:20:01Z",
      "end_time": "2025-07-29T15:20:25Z",
      "duration": 24,
      "result": "主机已成功隔离"
    }
  ],
  "start_time": "2025-07-29T15:20:00Z",
  "end_time": "2025-07-29T15:20:45Z",
  "total_duration": 45
}
```

### 5. 配置管理API

#### 5.1 获取系统配置

```http
GET /config/system
```

**响应**:
```json
{
  "version": "1.0.0",
  "build": "2025-07-29-1234",
  "ai_models": {
    "primary": "gpt-4",
    "fallback": "claude-3",
    "local": "llama-2-7b"
  },
  "data_retention": {
    "events": "90d",
    "logs": "30d",
    "analysis": "365d"
  },
  "features": {
    "auto_response": true,
    "threat_hunting": true,
    "ml_detection": true
  }
}
```

#### 5.2 更新系统配置

```http
PUT /config/system
```

**请求体**:
```json
{
  "ai_models": {
    "primary": "claude-3",
    "fallback": "gpt-4"
  },
  "features": {
    "auto_response": false
  }
}
```

### 6. 监控和指标API

#### 6.1 获取系统状态

```http
GET /health
```

**响应**:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2025-07-29T15:20:00Z",
  "services": {
    "api": "healthy",
    "database": "healthy",
    "cache": "healthy",
    "mcp_servers": "healthy"
  },
  "metrics": {
    "uptime": 86400,
    "memory_usage": 0.65,
    "cpu_usage": 0.23,
    "active_connections": 15
  }
}
```

#### 6.2 获取性能指标

```http
GET /metrics
```

**响应**:
```json
{
  "queries": {
    "total": 1247,
    "success_rate": 0.987,
    "avg_response_time": 2.3,
    "p95_response_time": 5.1
  },
  "threats": {
    "detected_today": 23,
    "blocked_today": 18,
    "false_positives": 2
  },
  "mcp_servers": {
    "total": 8,
    "healthy": 8,
    "avg_response_time": 0.8
  }
}
```

## 错误处理

### HTTP状态码

- `200` - 请求成功
- `201` - 资源创建成功
- `400` - 请求参数错误
- `401` - 未认证
- `403` - 权限不足
- `404` - 资源不存在
- `429` - 请求过于频繁
- `500` - 服务器内部错误
- `503` - 服务不可用

### 错误响应格式

```json
{
  "error": {
    "code": "INVALID_QUERY",
    "message": "查询参数格式不正确",
    "details": {
      "field": "time_range",
      "reason": "时间范围格式应为ISO 8601"
    },
    "request_id": "req-123456"
  }
}
```

## SDK和代码示例

### Python SDK示例

```python
from mcpsoc import MCPSocClient

# 初始化客户端
client = MCPSocClient(
    base_url="https://api.mcpsoc.org/v1",
    token="your-jwt-token"
)

# 自然语言查询
result = client.query.natural(
    query="查找过去24小时内的高危威胁事件",
    context={"severity": "high", "time_range": "24h"}
)

# 威胁指标分析
analysis = client.analysis.indicators([
    {"type": "ip", "value": "192.168.1.100"},
    {"type": "domain", "value": "malicious.com"}
])

# 执行响应行动
response_plan = client.response.create_plan(
    incident_id="incident-123",
    actions=[
        {"type": "block_ip", "target": "192.168.1.100"}
    ]
)
execution = client.response.execute_plan(response_plan.id)
```

### JavaScript SDK示例

```javascript
import { MCPSocClient } from '@mcpsoc/sdk';

const client = new MCPSocClient({
  baseURL: 'https://api.mcpsoc.org/v1',
  token: 'your-jwt-token'
});

// 自然语言查询
const result = await client.query.natural({
  query: '查找过去24小时内的高危威胁事件',
  context: { severity: 'high', timeRange: '24h' }
});

// 获取MCP服务状态
const servers = await client.mcp.getServers();
console.log(`连接的MCP服务数量: ${servers.total}`);
```

## API限制

- **请求频率**: 每分钟最多1000次请求
- **并发连接**: 每个API密钥最多100个并发连接
- **响应大小**: 单次响应最大10MB
- **超时时间**: API请求超时时间为30秒

## 版本更新

- **v1.0.0** (2025-07-29): 初始版本发布
- API向后兼容性保证
- 新功能通过新版本API发布
- 旧版本API将提供12个月的支持期

## 支持

如有API使用问题，请联系：
- 📧 api-support@mcpsoc.org
- 📚 文档: https://docs.mcpsoc.org
- 💬 社区: https://community.mcpsoc.org
