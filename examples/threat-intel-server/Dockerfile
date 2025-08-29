# 威胁情报MCP服务器Dockerfile
FROM golang:1.21-alpine AS builder

# 设置工作目录
WORKDIR /app

# 复制go mod文件
COPY go.mod go.sum ./

# 下载依赖
RUN go mod download

# 复制源代码
COPY examples/threat-intel-server/ ./

# 构建应用
RUN CGO_ENABLED=0 GOOS=linux go build -o threat-intel-server .

# 运行阶段
FROM alpine:latest

# 安装ca-certificates用于HTTPS请求
RUN apk --no-cache add ca-certificates

# 创建非root用户
RUN addgroup -g 1001 -S mcpsoc && \
    adduser -u 1001 -S mcpsoc -G mcpsoc

WORKDIR /app

# 复制二进制文件
COPY --from=builder /app/threat-intel-server .

# 更改所有权
RUN chown -R mcpsoc:mcpsoc /app

# 切换到非root用户
USER mcpsoc

# 暴露端口
EXPOSE 8083

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8083/health || exit 1

# 启动服务
CMD ["./threat-intel-server"]