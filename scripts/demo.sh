#!/bin/bash

# MCPSoc 演示脚本

set -e

echo "🎬 MCPSoc 演示开始"
echo "=================="

# API基础URL
API_URL="http://localhost:8080/api/v1"

echo ""
echo "1️⃣  检查系统健康状态"
echo "-------------------"
curl -s http://localhost:8080/health | jq '.'

echo ""
echo "2️⃣  查看MCP服务器状态"
echo "-------------------"
curl -s "$API_URL/mcp/servers" | jq '.'

echo ""
echo "3️⃣  自然语言安全查询演示"
echo "----------------------"
echo "查询: '查找过去24小时内的高危威胁事件'"

curl -s -X POST "$API_URL/query/natural" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "查找过去24小时内的高危威胁事件",
    "context": {
      "time_range": "24h",
      "severity": "high"
    }
  }' | jq '.'

echo ""
echo "4️⃣  结构化查询演示"
echo "----------------"
echo "查询安全事件数据库"

curl -s -X POST "$API_URL/query/structured" \
  -H "Content-Type: application/json" \
  -d '{
    "data_source": "security_events",
    "filters": {
      "severity": "high"
    },
    "limit": 5
  }' | jq '.'

echo ""
echo "5️⃣  MCP工具调用演示"
echo "-----------------"
echo "调用防火墙服务器的获取日志工具"

curl -s -X POST "$API_URL/mcp/servers/firewall-pfsense-01/tools/get_firewall_logs" \
  -H "Content-Type: application/json" \
  -d '{
    "arguments": {
      "time_range": "1h",
      "limit": 10
    }
  }' | jq '.'

echo ""
echo "6️⃣  IP阻止演示"
echo "------------"
echo "阻止可疑IP地址"

curl -s -X POST "$API_URL/mcp/servers/firewall-pfsense-01/tools/block_ip" \
  -H "Content-Type: application/json" \
  -d '{
    "arguments": {
      "ip_address": "192.168.1.100",
      "duration": 3600,
      "reason": "演示阻止可疑IP"
    }
  }' | jq '.'

echo ""
echo "7️⃣  获取被阻止的IP列表"
echo "-------------------"

curl -s -X POST "$API_URL/mcp/servers/firewall-pfsense-01/tools/get_blocked_ips" \
  -H "Content-Type: application/json" \
  -d '{
    "arguments": {
      "active_only": true
    }
  }' | jq '.'

echo ""
echo "8️⃣  获取防火墙规则"
echo "----------------"

curl -s -X POST "$API_URL/mcp/servers/firewall-pfsense-01/tools/get_firewall_rules" \
  -H "Content-Type: application/json" \
  -d '{
    "arguments": {}
  }' | jq '.'

echo ""
echo "🎉 演示完成!"
echo "==========="
echo ""
echo "💡 演示要点:"
echo "   • MCPSoc 支持自然语言安全查询"
echo "   • 通过MCP协议统一管理多种安全工具"
echo "   • 提供结构化查询和工具调用能力"
echo "   • 实现了开放式、可插拔的SOC架构"
echo ""
echo "🌐 Web界面: http://localhost:3000"
echo "📊 API文档: http://localhost:8080/health"
echo ""
echo "🔧 更多测试命令:"
echo "   • 查看服务状态: docker-compose ps"
echo "   • 查看日志: docker-compose logs -f mcpsoc-host"
echo "   • 停止服务: docker-compose down"