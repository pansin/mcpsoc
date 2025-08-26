# ModSecurity WAF MCP Server

ModSecurity WAF MCP Server是MCPSoc项目的一个核心组件，提供基于ModSecurity的Web应用防火墙功能，包括HTTP请求分析、攻击检测、IP阻止和安全配置管理。

## 功能特性

### 🛡️ 核心防护功能
- **HTTP请求分析**: 实时分析HTTP请求，检测各种Web攻击
- **攻击检测**: 检测SQL注入、XSS、文件包含、命令注入等攻击
- **IP阻止管理**: 自动和手动IP阻止功能
- **威胁评分**: 为每个请求计算威胁评分和风险等级

### 📊 安全管理
- **WAF规则管理**: 支持OWASP核心规则集和自定义规则
- **配置管理**: 实时更新WAF配置和安全策略
- **攻击日志**: 完整的攻击记录和审计日志
- **安全报告**: 生成详细的安全分析报告

### ⚙️ 高级功能
- **偏执级别调节**: 支持1-4级偏执级别配置
- **速率限制**: 基于IP的请求频率控制
- **地理阻止**: 支持按国家/地区阻止访问
- **白名单/黑名单**: 灵活的IP访问控制

## 工具列表

| 工具名称 | 描述 | 主要参数 |
|---------|------|---------|
| `analyze_request` | 分析HTTP请求威胁 | `request_data`, `paranoia_level` |
| `block_ip` | 阻止指定IP地址 | `ip_address`, `reason`, `duration` |
| `unblock_ip` | 解除IP阻止 | `ip_address` |
| `get_attack_logs` | 获取攻击日志 | `start_time`, `end_time`, `attack_type`, `severity` |
| `update_waf_config` | 更新WAF配置 | `mode`, `paranoia_level`, `ip_whitelist` |
| `create_custom_rule` | 创建自定义规则 | `name`, `rule_body`, `severity`, `action` |
| `test_rule` | 测试WAF规则 | `rule_id`, `test_requests` |
| `generate_report` | 生成安全报告 | `report_type`, `start_date`, `end_date`, `format` |

## 资源列表

| 资源URI | 描述 | 数据类型 |
|---------|------|----------|
| `modsec://config/current` | 当前WAF配置 | JSON |
| `modsec://rules/all` | 所有WAF规则 | JSON |
| `modsec://attacks/recent` | 最近攻击记录 | JSON |
| `modsec://blocked/ips` | 被阻止的IP列表 | JSON |
| `modsec://statistics/summary` | 统计摘要 | JSON |
| `modsec://logs/audit` | 审计日志 | Text |

## 安装和运行

### 前置要求
- Go 1.19+
- ModSecurity 3.0+ (实际部署时需要)

### 编译和运行
```bash
# 编译
go build -o modsecurity-server main.go handlers.go

# 运行
./modsecurity-server
```

服务器将在端口 8085 上启动。

### 健康检查
```bash
curl http://localhost:8085/health
```

## MCP 协议集成

### 初始化连接
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2024-11-05",
    "capabilities": {}
  }
}
```

### 分析HTTP请求示例
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "analyze_request",
    "arguments": {
      "request_data": {
        "method": "POST",
        "url": "/login",
        "body": "username=admin' OR '1'='1--&password=test",
        "headers": {
          "User-Agent": "Mozilla/5.0",
          "Content-Type": "application/x-www-form-urlencoded"
        },
        "source_ip": "192.168.1.100"
      },
      "paranoia_level": 2
    }
  }
}
```

### 阻止IP地址示例
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "block_ip",
    "arguments": {
      "ip_address": "192.168.1.100",
      "reason": "Multiple SQL injection attempts",
      "duration": 60
    }
  }
}
```

## 配置选项

环境变量配置：

- `MODSEC_PORT`: 服务端口 (默认: 8085)
- `MODSEC_HOST`: 服务主机 (默认: localhost)
- `MODSEC_MODE`: WAF模式 (learning, monitoring, blocking)
- `MODSEC_PARANOIA_LEVEL`: 偏执级别 (1-4)
- `MODSEC_LOG_LEVEL`: 日志级别 (debug, info, warn, error)

## 攻击检测类型

### 1. SQL注入检测
- 检测模式: `' OR '1'='1`, `UNION SELECT`, `DROP TABLE`
- 严重程度: High
- 默认动作: Block

### 2. XSS攻击检测  
- 检测模式: `<script>`, `javascript:`, `onclick=`
- 严重程度: Medium-High
- 默认动作: Warn/Block

### 3. 文件包含攻击
- 检测模式: `../`, `/etc/passwd`, `file://`
- 严重程度: Medium
- 默认动作: Block

### 4. 命令注入检测
- 检测模式: `|`, `&&`, `;`, 系统命令
- 严重程度: Critical
- 默认动作: Block

### 5. 恶意User-Agent
- 检测模式: `sqlmap`, `nikto`, `scanner`
- 严重程度: Medium
- 默认动作: Deny

## 使用场景

### 1. Web应用安全防护
```bash
# 分析可疑的登录请求
curl -X POST http://localhost:8085/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "analyze_request",
      "arguments": {
        "request_data": {
          "method": "POST",
          "url": "/admin/login",
          "body": "username=admin&password=password123",
          "source_ip": "203.0.113.10"
        }
      }
    }
  }'
```

### 2. 自动威胁响应
```bash
# 自动阻止攻击IP
curl -X POST http://localhost:8085/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "block_ip",
      "arguments": {
        "ip_address": "203.0.113.100",
        "reason": "Automated blocking due to SQL injection",
        "duration": 1440
      }
    }
  }'
```

### 3. 安全运营分析
```bash
# 获取攻击趋势报告
curl -X POST http://localhost:8085/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
      "name": "generate_report",
      "arguments": {
        "report_type": "attack_summary",
        "start_date": "2024-01-01",
        "end_date": "2024-01-31",
        "format": "json"
      }
    }
  }'
```

## WAF配置管理

### 模式切换
- **Learning**: 学习模式，记录但不阻止
- **Monitoring**: 监控模式，记录和警告
- **Blocking**: 阻止模式，主动防护

### 偏执级别
- **Level 1**: 基础防护，低误报
- **Level 2**: 平衡防护，推荐设置  
- **Level 3**: 严格防护，可能误报
- **Level 4**: 最严格，高误报率

## 集成到MCPSoc

ModSecurity WAF MCP Server作为MCPSoc安全运营中心的Web应用防护组件：

- **与SIEM集成**: 将攻击事件发送到SIEM系统进行关联分析
- **与威胁情报联动**: 结合威胁情报数据进行高级威胁检测
- **与SOAR协同**: 自动化威胁响应和事件处理流程
- **与其他防护组件协同**: 与防火墙、IPS等组件形成多层防护

## 性能和扩展

### 性能指标
- 请求处理延迟: < 10ms (典型)
- 并发处理能力: 1000+ requests/second
- 内存占用: < 100MB (基础配置)
- CPU占用: < 5% (正常负载)

### 扩展能力
- 支持水平扩展部署
- 支持负载均衡配置
- 支持集群模式运行
- 支持容器化部署

## 开发和贡献

### 代码结构
```
modsecurity-server/
├── main.go         # 主服务器和数据结构
├── handlers.go     # 工具处理器实现
└── README.md       # 文档
```

### 添加新检测规则
1. 在 `loadDefaultRules()` 中定义新规则
2. 在 `analyzeHTTPRequest()` 中实现检测逻辑
3. 在相关工具中添加处理逻辑
4. 更新文档和测试

## 许可证

Apache 2.0 许可证 - 查看 [LICENSE](../../LICENSE) 文件了解详情

## 相关链接

- [MCPSoc 主项目](../../README.md)
- [MCP 协议规范](https://spec.modelcontextprotocol.io/)
- [ModSecurity 官方文档](https://github.com/SpiderLabs/ModSecurity)
- [OWASP 核心规则集](https://owasp.org/www-project-modsecurity-core-rule-set/)