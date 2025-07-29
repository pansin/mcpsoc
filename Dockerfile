# 多阶段构建 Dockerfile

# 构建阶段
FROM golang:1.21-alpine AS builder

# 安装必要的包
RUN apk add --no-cache git ca-certificates tzdata

# 设置工作目录
WORKDIR /app

# 复制 go mod 文件
COPY go.mod go.sum ./

# 下载依赖
RUN go mod download

# 复制源代码
COPY . .

# 构建应用
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o mcpsoc-host ./cmd/mcpsoc-host

# 运行阶段
FROM alpine:latest

# 安装必要的包
RUN apk --no-cache add ca-certificates tzdata

# 创建非root用户
RUN addgroup -g 1001 -S mcpsoc && \
    adduser -u 1001 -S mcpsoc -G mcpsoc

# 设置工作目录
WORKDIR /app

# 从构建阶段复制二进制文件
COPY --from=builder /app/mcpsoc-host .

# 复制配置文件
COPY --chown=mcpsoc:mcpsoc config/ ./config/

# 创建日志目录
RUN mkdir -p logs && chown mcpsoc:mcpsoc logs

# 切换到非root用户
USER mcpsoc

# 暴露端口
EXPOSE 8080

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# 启动应用
CMD ["./mcpsoc-host", "--config", "config/config.yaml"]