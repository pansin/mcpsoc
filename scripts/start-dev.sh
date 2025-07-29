#!/bin/bash

# MCPSoc 开发环境启动脚本

set -e

echo "🚀 启动 MCPSoc 开发环境..."

# 检查Docker是否运行
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker 未运行，请先启动 Docker"
    exit 1
fi

# 检查环境变量
if [ -z "$OPENAI_API_KEY" ]; then
    echo "⚠️  警告: OPENAI_API_KEY 环境变量未设置"
fi

if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo "⚠️  警告: ANTHROPIC_API_KEY 环境变量未设置"
fi

# 创建必要的目录
mkdir -p logs
mkdir -p data/postgres
mkdir -p data/redis

# 启动基础服务
echo "📦 启动基础服务 (PostgreSQL, Redis)..."
docker-compose up -d postgres redis

# 等待数据库启动
echo "⏳ 等待数据库启动..."
sleep 10

# 检查数据库连接
echo "🔍 检查数据库连接..."
until docker-compose exec -T postgres pg_isready -U mcpsoc -d mcpsoc; do
    echo "等待数据库连接..."
    sleep 2
done

echo "✅ 数据库已就绪"

# 构建并启动应用服务
echo "🔨 构建并启动应用服务..."
docker-compose up -d --build mcpsoc-host firewall-server

# 启动前端开发服务器
echo "🌐 启动前端开发服务器..."
docker-compose up -d web-dev

# 等待服务启动
echo "⏳ 等待服务启动..."
sleep 15

# 检查服务状态
echo "🔍 检查服务状态..."

# 检查主服务
if curl -f http://localhost:8080/health > /dev/null 2>&1; then
    echo "✅ MCPSoc Host 服务正常 (http://localhost:8080)"
else
    echo "❌ MCPSoc Host 服务启动失败"
fi

# 检查防火墙服务器
if curl -f http://localhost:8081/health > /dev/null 2>&1; then
    echo "✅ 防火墙 MCP Server 正常 (http://localhost:8081)"
else
    echo "❌ 防火墙 MCP Server 启动失败"
fi

# 检查前端服务
if curl -f http://localhost:3000 > /dev/null 2>&1; then
    echo "✅ Web 界面正常 (http://localhost:3000)"
else
    echo "❌ Web 界面启动失败"
fi

echo ""
echo "🎉 MCPSoc 开发环境启动完成!"
echo ""
echo "📋 服务地址:"
echo "   • Web 界面:        http://localhost:3000"
echo "   • API 服务:        http://localhost:8080"
echo "   • 防火墙 MCP:      http://localhost:8081"
echo "   • PostgreSQL:      localhost:5432"
echo "   • Redis:           localhost:6379"
echo ""
echo "🔧 常用命令:"
echo "   • 查看日志:        docker-compose logs -f"
echo "   • 停止服务:        docker-compose down"
echo "   • 重启服务:        docker-compose restart"
echo "   • 查看状态:        docker-compose ps"
echo ""
echo "📖 API 文档: http://localhost:8080/health"
echo "🔍 测试查询: curl -X POST http://localhost:8080/api/v1/query/natural -H 'Content-Type: application/json' -d '{\"query\":\"查找高危威胁事件\"}'"