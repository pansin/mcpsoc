# ClamAV MCP Server

ClamAV MCP Server是MCPSoc项目的一个组件，提供基于ClamAV防病毒引擎的文件扫描和威胁检测功能。

## 功能特性

### 🔍 核心扫描功能
- **文件扫描**: 扫描单个文件，检测病毒和恶意软件
- **目录扫描**: 递归扫描整个目录，支持文件类型过滤
- **快速扫描**: 快速扫描系统关键区域（内存、启动项、临时文件等）
- **实时保护**: 提供实时文件监控和威胁检测

### 🛡️ 威胁管理
- **文件隔离**: 自动隔离检测到的威胁文件
- **隔离恢复**: 从隔离区恢复误报文件
- **恶意软件分析**: 深度分析恶意软件样本
- **威胁情报**: 提供IOC指标和威胁信息

### 📊 监控和报告
- **扫描历史**: 完整的扫描历史记录
- **统计报告**: 威胁检测统计和趋势分析
- **实时日志**: 实时扫描活动日志
- **病毒库管理**: 病毒库更新和版本管理

## 工具列表

| 工具名称 | 描述 | 主要参数 |
|---------|------|---------|
| `scan_file` | 扫描单个文件 | `file_path`, `scan_options` |
| `scan_directory` | 扫描目录 | `directory_path`, `recursive`, `file_types` |
| `quick_scan` | 快速系统扫描 | `scan_areas`, `priority` |
| `update_database` | 更新病毒库 | `force_update`, `check_only` |
| `quarantine_file` | 隔离文件 | `file_path`, `threat_name`, `reason` |
| `restore_quarantine` | 恢复隔离文件 | `quarantine_id`, `restore_path` |
| `get_scan_history` | 获取扫描历史 | `start_date`, `end_date`, `status_filter` |
| `analyze_malware` | 恶意软件分析 | `file_path`, `analysis_type`, `sandbox` |

## 资源列表

| 资源URI | 描述 | 数据类型 |
|---------|------|----------|
| `clamav://database/info` | 病毒库信息 | JSON |
| `clamav://scan/history` | 扫描历史记录 | JSON |
| `clamav://quarantine/list` | 隔离文件列表 | JSON |
| `clamav://statistics/summary` | 统计摘要 | JSON |
| `clamav://logs/realtime` | 实时日志 | Text |

## 安装和运行

### 前置要求
- Go 1.19+
- ClamAV 1.0+ (实际部署时需要)

### 编译和运行
```bash
# 编译
go build -o clamav-server main.go handlers.go resources.go

# 运行
./clamav-server
```

服务器将在端口 8084 上启动。

### 健康检查
```bash
curl http://localhost:8084/health
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

### 调用工具示例
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "scan_file",
    "arguments": {
      "file_path": "/tmp/test.exe",
      "scan_options": {
        "deep_scan": true,
        "detect_pua": true
      }
    }
  }
}
```

### 读取资源示例
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "resources/read",
  "params": {
    "uri": "clamav://scan/history"
  }
}
```

## 配置选项

环境变量配置：

- `CLAMAV_PORT`: 服务端口 (默认: 8084)
- `CLAMAV_HOST`: 服务主机 (默认: localhost)
- `CLAMAV_DB_PATH`: 病毒库路径
- `CLAMAV_QUARANTINE_PATH`: 隔离目录路径
- `CLAMAV_LOG_LEVEL`: 日志级别 (debug, info, warn, error)

## 使用场景

### 1. 文件上传安全检查
```bash
# 检查用户上传的文件
curl -X POST http://localhost:8084/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "scan_file",
      "arguments": {
        "file_path": "/uploads/user_file.exe"
      }
    }
  }'
```

### 2. 定期安全扫描
```bash
# 扫描下载目录
curl -X POST http://localhost:8084/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "scan_directory",
      "arguments": {
        "directory_path": "/home/user/Downloads",
        "recursive": true,
        "file_types": ["exe", "zip", "rar"]
      }
    }
  }'
```

### 3. 威胁情报分析
```bash
# 分析可疑文件
curl -X POST http://localhost:8084/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
      "name": "analyze_malware",
      "arguments": {
        "file_path": "/quarantine/suspicious.exe",
        "analysis_type": "detailed",
        "sandbox": true
      }
    }
  }'
```

## 集成到MCPSoc

ClamAV MCP Server作为MCPSoc安全运营中心的防病毒组件，可以与其他安全工具协同工作：

- **与威胁情报服务联动**: 将检测到的威胁提交给威胁情报系统进行进一步分析
- **与SIEM集成**: 将扫描结果和威胁事件发送到SIEM系统
- **与SOAR协同**: 通过SOAR系统自动化威胁响应流程

## 开发和贡献

### 代码结构
```
clamav-server/
├── main.go         # 主服务器和路由
├── handlers.go     # 工具处理器实现
├── resources.go    # 资源处理器实现
└── README.md       # 文档
```

### 添加新功能
1. 在 `initializeTools()` 中定义新工具
2. 在 `handlers.go` 中实现处理逻辑
3. 在 `HandleToolCall()` 中添加路由
4. 更新文档和测试

## 许可证

Apache 2.0 许可证 - 查看 [LICENSE](../../LICENSE) 文件了解详情

## 相关链接

- [MCPSoc 主项目](../../README.md)
- [MCP 协议规范](https://spec.modelcontextprotocol.io/)
- [ClamAV 官方文档](https://docs.clamav.net/)