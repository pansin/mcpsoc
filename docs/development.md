# MCPSoc 开发指南

## 开发环境搭建

### 系统要求

- **操作系统**: Linux (Ubuntu 20.04+), macOS (10.15+), Windows 10+
- **Go版本**: >= 1.21
- **Docker**: >= 20.10
- **Docker Compose**: >= 2.0
- **Git**: >= 2.30

### 本地开发环境

1. **克隆代码仓库**
```bash
git clone https://github.com/mcpsoc/mcpsoc.git
cd mcpsoc
```

2. **安装依赖**
```bash
# 安装Go依赖
go mod download

# 安装开发工具
make install-tools
```

3. **配置环境变量**
```bash
cp .env.example .env
# 编辑 .env 文件，设置数据库连接和API密钥
```

4. **启动依赖服务**
```bash
docker-compose -f docker-compose.dev.yml up -d
```

5. **初始化数据库**
```bash
make db-migrate
make db-seed
```

6. **运行开发服务器**
```bash
make dev
```

## 项目结构

```
mcpsoc/
├── cmd/                    # 应用程序入口
│   ├── mcpsoc-host/       # MCP Host 服务
│   ├── mcpsoc-agent/      # MCPSoc Agent
│   └── mcpsoc-cli/        # 命令行工具
├── internal/              # 内部代码包
│   ├── agent/             # AI Agent 组件
│   ├── api/               # API 路由和处理器
│   ├── auth/              # 认证和授权
│   ├── config/            # 配置管理
│   ├── database/          # 数据库操作
│   ├── mcp/               # MCP 协议实现
│   ├── query/             # 查询处理引擎
│   ├── analysis/          # 威胁分析引擎
│   ├── response/          # 响应行动引擎
│   └── workflow/          # 工作流编排
├── pkg/                   # 公共代码包
│   ├── mcp-sdk/           # MCP SDK
│   ├── security/          # 安全工具包
│   └── utils/             # 通用工具
├── examples/              # MCP Server 示例
│   ├── firewall-server/   # 防火墙 MCP Server
│   ├── waf-server/        # WAF MCP Server
│   └── av-server/         # 杀毒软件 MCP Server
├── web/                   # Web 前端
│   ├── src/
│   ├── public/
│   └── package.json
├── docs/                  # 文档
├── scripts/               # 脚本文件
├── deployments/           # 部署配置
├── tests/                 # 测试文件
├── Makefile              # 构建脚本
├── docker-compose.yml    # Docker 编排
└── go.mod                # Go 模块定义
```

## 开发规范

### Go 代码规范

1. **包命名**
```go
// 好的包名
package mcp
package analysis
package workflow

// 避免的包名
package utils
package common
package helpers
```

2. **接口设计**
```go
// 好的接口设计
type QueryProcessor interface {
    ProcessQuery(ctx context.Context, query *Query) (*Result, error)
}

type ThreatAnalyzer interface {
    AnalyzeIndicators(ctx context.Context, indicators []IOC) (*Analysis, error)
}

// 接口应该小而专注，遵循单一职责原则
```

3. **错误处理**
```go
// 使用自定义错误类型
type MCPError struct {
    Code    string `json:"code"`
    Message string `json:"message"`
    Details map[string]interface{} `json:"details,omitempty"`
}

func (e *MCPError) Error() string {
    return fmt.Sprintf("MCP Error [%s]: %s", e.Code, e.Message)
}

// 错误包装
if err != nil {
    return nil, fmt.Errorf("failed to process query: %w", err)
}
```

4. **日志记录**
```go
// 使用结构化日志
import "github.com/sirupsen/logrus"

logger := logrus.WithFields(logrus.Fields{
    "component": "query-processor",
    "query_id":  query.ID,
    "user_id":   query.UserID,
})
logger.Info("Processing query")
```

### MCP Server 开发指南

1. **创建新的 MCP Server**

```bash
# 使用脚手架生成器
go run scripts/create-mcp-server.go --name=my-security-tool
```

2. **MCP Server 结构**

```go
package main

import (
    "context"
    "github.com/mcpsoc/mcpsoc/pkg/mcp-sdk"
)

type MySecurityToolServer struct {
    mcpsdk.BaseServer
    client *MySecurityToolClient
}

func (s *MySecurityToolServer) GetTools() []mcpsdk.Tool {
    return []mcpsdk.Tool{
        {
            Name:        "scan_host",
            Description: "扫描指定主机的安全漏洞",
            InputSchema: mcpsdk.JSONSchema{
                Type: "object",
                Properties: map[string]mcpsdk.JSONSchema{
                    "host": {Type: "string", Description: "目标主机IP或域名"},
                    "scan_type": {Type: "string", Enum: []string{"quick", "full"}},
                },
                Required: []string{"host"},
            },
            Handler: s.handleScanHost,
        },
    }
}

func (s *MySecurityToolServer) handleScanHost(ctx context.Context, args map[string]interface{}) (*mcpsdk.ToolResult, error) {
    host, ok := args["host"].(string)
    if !ok {
        return nil, mcpsdk.NewMCPError("INVALID_INPUT", "host parameter is required")
    }
    
    // 执行扫描逻辑
    result, err := s.client.ScanHost(ctx, host)
    if err != nil {
        return nil, fmt.Errorf("scan failed: %w", err)
    }
    
    return &mcpsdk.ToolResult{
        Content: []mcpsdk.Content{
            {
                Type: "text",
                Text: fmt.Sprintf("扫描完成，发现 %d 个漏洞", len(result.Vulnerabilities)),
            },
            {
                Type: "application/json",
                Text: string(result.ToJSON()),
            },
        },
    }, nil
}
```

3. **配置文件**

```yaml
# config/my-security-tool.yaml
server:
  name: "My Security Tool"
  version: "1.0.0"
  description: "我的安全工具MCP Server"
  transport: "stdio"
  
credentials:
  api_key: "${MY_TOOL_API_KEY}"
  endpoint: "https://api.mytool.com"
  
logging:
  level: "info"
  format: "json"
```

### 前端开发指南

1. **技术栈**
- React 18
- TypeScript
- Vite
- Tailwind CSS
- React Query
- Zustand

2. **启动前端开发服务器**

```bash
cd web
npm install
npm run dev
```

3. **组件结构**

```tsx
// src/components/QueryInterface.tsx
import React, { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { submitQuery } from '../api/queries';

interface QueryInterfaceProps {
  onResult: (result: QueryResult) => void;
}

export const QueryInterface: React.FC<QueryInterfaceProps> = ({ onResult }) => {
  const [query, setQuery] = useState('');
  
  const queryMutation = useMutation({
    mutationFn: submitQuery,
    onSuccess: (data) => {
      onResult(data);
    },
  });
  
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    queryMutation.mutate({ query });
  };
  
  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <textarea
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        placeholder="输入您的安全查询..."
        className="w-full h-32 p-3 border rounded-lg"
      />
      <button
        type="submit"
        disabled={queryMutation.isPending}
        className="px-6 py-2 bg-blue-600 text-white rounded-lg"
      >
        {queryMutation.isPending ? '分析中...' : '提交查询'}
      </button>
    </form>
  );
};
```

## 测试指南

### 单元测试

```bash
# 运行所有单元测试
make test

# 运行特定包的测试
go test ./internal/query/...

# 运行测试并生成覆盖率报告
make test-coverage
```

**测试示例**:
```go
// internal/query/processor_test.go
func TestQueryProcessor_ProcessQuery(t *testing.T) {
    tests := []struct {
        name    string
        query   *Query
        want    *Result
        wantErr bool
    }{
        {
            name: "valid security query",
            query: &Query{
                Text: "查找过去1小时内的高危威胁",
                Context: map[string]interface{}{
                    "time_range": "1h",
                    "severity": "high",
                },
            },
            want: &Result{
                Summary: "发现5个高危威胁事件",
                Data: []SecurityEvent{
                    {ID: "event-1", Severity: "high"},
                },
            },
            wantErr: false,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            processor := NewQueryProcessor(mockMCPClient, mockAIAgent)
            result, err := processor.ProcessQuery(context.Background(), tt.query)
            
            if tt.wantErr {
                assert.Error(t, err)
                return
            }
            
            assert.NoError(t, err)
            assert.Equal(t, tt.want.Summary, result.Summary)
        })
    }
}
```

### 集成测试

```bash
# 运行集成测试
make test-integration

# 使用Docker运行集成测试
make test-integration-docker
```

### E2E 测试

```bash
# 运行端到端测试
make test-e2e
```

## 构建和部署

### 本地构建

```bash
# 构建所有组件
make build

# 构建特定组件
make build-host
make build-agent
make build-cli

# 构建 Docker 镜像
make docker-build
```

### CI/CD 流程

**GitHub Actions 配置**:
```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Go
      uses: actions/setup-go@v3
      with:
        go-version: 1.21
    
    - name: Cache Go modules
      uses: actions/cache@v3
      with:
        path: ~/go/pkg/mod
        key: ${{ runner.os }}-go-${{ hashFiles('**/go.sum') }}
    
    - name: Run tests
      run: make test-coverage
    
    - name: Upload coverage
      uses: codecov/codecov-action@v3
  
  build:
    runs-on: ubuntu-latest
    needs: test
    steps:
    - uses: actions/checkout@v3
    
    - name: Build Docker images
      run: make docker-build
    
    - name: Push to registry
      if: github.ref == 'refs/heads/main'
      run: make docker-push
```

## 调试指南

### 启用调试模式

```bash
# 启用详细日志
export LOG_LEVEL=debug
export MCP_DEBUG=true

# 运行服务
go run cmd/mcpsoc-host/main.go
```

### 使用 Delve 调试器

```bash
# 安装 Delve
go install github.com/go-delve/delve/cmd/dlv@latest

# 启动调试服务
dlv debug cmd/mcpsoc-host/main.go

# 设置断点
(dlv) break main.main
(dlv) continue
```

### VS Code 调试配置

```json
// .vscode/launch.json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Debug MCPSoc Host",
            "type": "go",
            "request": "launch",
            "mode": "debug",
            "program": "${workspaceFolder}/cmd/mcpsoc-host",
            "env": {
                "LOG_LEVEL": "debug",
                "MCP_DEBUG": "true"
            },
            "args": []
        }
    ]
}
```

## 性能优化

### 性能分析

```bash
# CPU 性能分析
go test -cpuprofile=cpu.prof -bench=.
go tool pprof cpu.prof

# 内存性能分析
go test -memprofile=mem.prof -bench=.
go tool pprof mem.prof

# 在线性能监控
curl http://localhost:8080/debug/pprof/
```

### 性能优化建议

1. **数据库优化**
   - 使用连接池
   - 添加适当的索引
   - 使用数据库预处理语句

2. **缓存优化**
   - 使用 Redis 缓存热点数据
   - 实现分层缓存策略
   - 使用 CDN 加速静态资源

3. **并发优化**
   - 使用 goroutine 池
   - 实现请求率限制
   - 优化锁竞争

## 贡献指南

### 代码贡献流程

1. **Fork 项目**
2. **创建功能分支**
   ```bash
   git checkout -b feature/my-new-feature
   ```

3. **提交代码**
   ```bash
   git commit -am 'Add some feature'
   ```

4. **推送到分支**
   ```bash
   git push origin feature/my-new-feature
   ```

5. **创建 Pull Request**

### 代码审查标准

- [ ] 代码遵循项目编码规范
- [ ] 包含适当的单元测试
- [ ] 通过所有CI检查
- [ ] 更新相关文档
- [ ] 添加或更新变更日志

### Commit 信息规范

```
type(scope): subject

body

footer
```

**类型**:
- `feat`: 新功能
- `fix`: Bug修复
- `docs`: 文档更新
- `style`: 代码格式调整
- `refactor`: 代码重构
- `perf`: 性能优化
- `test`: 测试添加或修改
- `chore`: 构建或辅助工具变动

**示例**:
```
feat(mcp): add new firewall server support

Implement pfSense MCP server with basic tools:
- block_ip: Block specific IP address
- get_logs: Retrieve firewall logs
- get_rules: List current firewall rules

Closes #123
```

## 常见问题

### Q: 如何添加新的 MCP Server？

A: 使用脚手架生成器创建基础结构，然后实现必要的接口方法。详细步骤请参考 MCP Server 开发指南部分。

### Q: 如何调试 MCP 协议通信？

A: 设置环境变量 `MCP_DEBUG=true`，系统将输出详细的协议通信日志。

### Q: 如何添加新的 AI 模型支持？

A: 在 `internal/agent/providers/` 目录下创建新的提供商实现，并在配置文件中注册。

### Q: 如何优化查询性能？

A: 可以从以下几个方面优化：
- 使用缓存常用查询结果
- 优化数据库查询和索引
- 实现查询结果分页
- 使用并发查询处理

## 相关资源

- [Go 编码规范](https://golang.org/doc/effective_go.html)
- [MCP 协议规范](https://spec.modelcontextprotocol.io/)
- [Docker 最佳实践](https://docs.docker.com/develop/dev-best-practices/)
- [Kubernetes 部署指南](https://kubernetes.io/docs/concepts/workloads/deployment/)
