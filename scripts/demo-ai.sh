#!/bin/bash

# MCPSoc AI功能演示脚本

set -e

echo "🤖 MCPSoc AI功能演示"
echo "==================="

# API基础URL
API_URL="http://localhost:8080/api/v1"

echo ""
echo "1️⃣  检查系统健康状态"
echo "-------------------"
curl -s http://localhost:8080/health | jq '.'

echo ""
echo "2️⃣  智能自然语言查询演示"
echo "----------------------"

# 威胁分析查询
echo "查询: '分析过去24小时内的安全威胁'"
curl -s -X POST "$API_URL/query/natural" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "分析过去24小时内的安全威胁",
    "context": {
      "time_range": "24h",
      "severity": "high"
    },
    "session_id": "demo-session-001"
  }' | jq '.'

echo ""
echo "3️⃣  防火墙安全查询"
echo "----------------"
echo "查询: '查找被防火墙阻止的可疑连接'"

curl -s -X POST "$API_URL/query/natural" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "查找被防火墙阻止的可疑连接",
    "context": {
      "source": "firewall",
      "action": "blocked"
    },
    "session_id": "demo-session-002"
  }' | jq '.'

echo ""
echo "4️⃣  威胁情报查询"
echo "---------------"
echo "查询: '搜索相关的威胁指标和IOC'"

curl -s -X POST "$API_URL/query/natural" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "搜索相关的威胁指标和IOC",
    "context": {
      "ip": "192.168.1.100",
      "indicators": ["ip", "domain", "hash"]
    },
    "session_id": "demo-session-003"
  }' | jq '.'

echo ""
echo "5️⃣  日志分析查询"
echo "---------------"
echo "查询: '分析系统日志中的异常模式'"

curl -s -X POST "$API_URL/query/natural" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "分析系统日志中的异常模式",
    "context": {
      "log_sources": ["firewall", "waf", "system"],
      "time_range": "1h"
    },
    "session_id": "demo-session-004"
  }' | jq '.'

echo ""
echo "6️⃣  事件响应查询"
echo "---------------"
echo "查询: '为检测到的安全事件生成响应计划'"

curl -s -X POST "$API_URL/query/natural" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "为检测到的安全事件生成响应计划",
    "context": {
      "incident_type": "malware_detection",
      "severity": "high",
      "affected_systems": ["web-server-01", "db-server-02"]
    },
    "session_id": "demo-session-005"
  }' | jq '.'

echo ""
echo "7️⃣  复杂安全查询"
echo "---------------"
echo "查询: '查找过去一周内的高危漏洞并评估风险'"

curl -s -X POST "$API_URL/query/natural" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "查找过去一周内的高危漏洞并评估风险",
    "context": {
      "time_range": "7d",
      "severity": ["high", "critical"],
      "asset_types": ["web", "database", "network"]
    },
    "session_id": "demo-session-006"
  }' | jq '.'

echo ""
echo "8️⃣  MCP服务器状态检查"
echo "-------------------"
curl -s "$API_URL/mcp/servers" | jq '.'

echo ""
echo "🎯 AI功能演示完成！"
echo "==================="
echo ""
echo "主要特性展示："
echo "✅ 自然语言查询解析"
echo "✅ 智能意图识别"
echo "✅ MCP工具调用编排"
echo "✅ 威胁分析和响应"
echo "✅ 多数据源关联分析"
echo "✅ 智能推荐和洞察"
echo ""
echo "可以通过以下方式进一步测试："
echo "1. 修改查询内容测试不同的安全场景"
echo "2. 调整上下文参数观察AI响应变化"
echo "3. 使用不同的会话ID测试会话管理"
echo "4. 查看详细的API响应了解AI分析过程"