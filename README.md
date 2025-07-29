# MCPSoc - 基于MCP协议的开放式智能安全运营中心

![MCPSoc Logo](https://img.shields.io/badge/MCPSoc-v1.0.0-blue)
![License](https://img.shields.io/badge/license-Apache%202.0-green)
![Go Version](https://img.shields.io/badge/go-%3E%3D1.21-blue)
![MCP Protocol](https://img.shields.io/badge/MCP-2025--06--18-orange)

## 🚀 项目简介

MCPSoc（Model Context Protocol Security Operations Center）是首个基于MCP协议构建的开放式、可插拔的智能安全运营中心。项目旨在打破传统SOC解决方案的"围墙花园"困境，通过标准化的MCP接口实现AI与安全工具的完全解耦，构建真正开放、灵活、高效的统一数据驱动型安全运营体系。

### ✨ 核心特性

- 🔌 **开放式架构**: 基于MCP协议，支持任意第三方安全工具无缝接入
- 🤖 **AI原生设计**: 内置大模型集成，支持自然语言查询和智能分析
- 🔄 **标准化接口**: 统一的数据格式和API，消除数据孤岛
- 🛡️ **全面安全覆盖**: 支持防火墙、WAF、杀毒软件、威胁情报等多种数据源
- ⚡ **高性能处理**: Go语言开发，支持大规模并发和水平扩展
- 🔧 **灵活部署**: 支持本地部署、云端部署和混合部署模式

## 🏗️ 系统架构

```
┌─────────────────────────────────────────────────────────────┐
│                    MCPSoc AI SOC Platform                   │
│  ┌──────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │ NL Query UI  │  │ MCP Host    │  │ MCPSoc Agent        │ │
│  │              │  │ Service     │  │ (AI Engine)         │ │
│  └──────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                              │
                    ┌─────────┴─────────┐
                    │   MCP Protocol    │
                    │   (JSON-RPC 2.0)  │
                    └─────────┬─────────┘
                              │
┌─────────────────────────────┴─────────────────────────────┐
│                    MCP Server Layer                       │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────────┐  │
│  │Firewall  │ │   WAF    │ │    AV    │ │  Threat     │  │
│  │MCP Server│ │MCP Server│ │MCP Server│ │  Intel      │  │
│  └──────────┘ └──────────┘ └──────────┘ │  MCP Server │  │
│                                         └─────────────┘  │
└───────────────────────────────────────────────────────────┘
```

## 🎯 核心组件

### MCP Host 服务
- **自然语言处理**: 理解安全分析师的查询意图
- **任务编排**: 将复杂查询分解为标准化工具调用
- **数据融合**: 跨域安全数据关联和综合分析
- **智能响应**: 自动化威胁检测和应急响应

### MCPSoc Agent
- **多模型支持**: 集成OpenAI、Claude、本地模型等
- **威胁分析**: AI驱动的安全事件分析和关联
- **知识库**: 向量化安全知识库和RAG系统
- **持续学习**: 基于反馈的模型优化

### MCP Server 框架
- **多语言SDK**: 支持Go、Python、Node.js开发
- **标准化封装**: 统一的安全工具MCP化框架
- **认证授权**: 内置安全认证和权限管理
- **监控审计**: 完整的日志记录和性能监控

## 🔧 支持的安全工具

### 防火墙
- ✅ pfSense/OPNsense
- ✅ FortiGate
- ✅ Palo Alto Networks
- ✅ iptables/ufw

### Web应用防火墙
- ✅ ModSecurity
- ✅ AWS WAF
- ✅ Cloudflare WAF
- ✅ NGINX ModSecurity

### 杀毒软件
- ✅ ClamAV
- ✅ Windows Defender
- ✅ 企业级EDR解决方案

### 威胁情报
- ✅ STIX/TAXII 2.0
- ✅ MISP
- ✅ 商业威胁情报源
- ✅ 开源IOC源

## 🚀 快速开始

### 系统要求
- Go >= 1.21
- PostgreSQL >= 14 (推荐TimescaleDB)
- Redis >= 6.0
- Docker (可选)

### 安装步骤

1. **克隆项目**
```bash
git clone https://github.com/your-org/mcpsoc.git
cd mcpsoc
```

2. **配置环境**
```bash
cp config/config.example.yaml config/config.yaml
# 编辑配置文件
```

3. **安装依赖**
```bash
go mod download
```

4. **初始化数据库**
```bash
make db-migrate
```

5. **启动服务**
```bash
make run
```

### Docker 部署

```bash
docker-compose up -d
```

## 📊 使用示例

### 自然语言查询
```
"分析用户 john@company.com 的设备上是否有与 malicious.com 相关的可疑活动"
```

### API调用
```bash
curl -X POST http://localhost:8080/api/v1/query \
  -H "Content-Type: application/json" \
  -d '{
    "query": "检查防火墙日志中的异常流量",
    "context": {
      "time_range": "last_24h",
      "severity": "high"
    }
  }'
```

## 🏢 商业模式

### 开源核心
- ✅ MCP Server SDK
- ✅ MCP Client 组件
- ✅ MCP Host 核心功能
- ✅ 基础安全工具集成

### 企业版增值功能
- 🚀 企业级管理面板
- 🚀 高级威胁分析
- 🚀 自定义工作流
- 🚀 企业级支持和培训

## 📖 文档

- [架构设计](./docs/architecture.md)
- [API文档](./docs/api.md)
- [开发指南](./docs/development.md)
- [部署指南](./docs/deployment.md)
- [MCP Server开发](./docs/mcp-server-development.md)

## 🤝 贡献指南

我们欢迎社区贡献！请查看 [CONTRIBUTING.md](./CONTRIBUTING.md) 了解如何参与项目开发。

### 贡献方式
- 🐛 报告Bug
- 💡 提出新功能建议
- 📝 改进文档
- 🔧 提交代码
- 🔌 开发MCP Server插件

## 📝 许可证

本项目采用 [Apache 2.0](./LICENSE) 许可证。

## 🙏 致谢

感谢 [Anthropic](https://anthropic.com) 开发的 MCP 协议，为构建开放式AI系统提供了技术基础。

## 📞 联系我们

- 🌐 官网: https://mcpsoc.org
- 📧 邮箱: info@mcpsoc.org
- 💬 Discord: https://discord.gg/mcpsoc
- 🐦 Twitter: @MCPSoc

---

**让安全运营更加开放、智能、高效** 🛡️✨