# 第一阶段：使用Go镜像编译
FROM golang:1.24.1-alpine AS builder

# 设置工作目录
WORKDIR /app

# 复制Go模块文件（先复制go.mod和go.sum可以提高构建缓存效率）
COPY go.mod go.sum ./
RUN go mod download

# 复制源代码
COPY . .

# 编译应用程序（禁用CGO并静态链接）
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-w -s" -o middleware_linux_amd64 main.go

# 第二阶段：使用Alpine运行
FROM alpine:latest

# 安装CA证书（用于HTTPS连接）
RUN apk --no-cache add ca-certificates

# 设置工作目录
WORKDIR /app

# 从builder阶段复制编译好的二进制文件
COPY --from=builder /app/middleware_linux_amd64 /app/

# 设置环境变量默认值
ENV WS_PORT=8080 \
    TCP_HOST="" \
    TCP_PORT=6666

# 设置执行权限
RUN chmod +x /app/middleware_linux_amd64

# 设置容器启动命令（使用环境变量）
CMD ./middleware_linux_amd64 \
    -ws-port=${WS_PORT} \
    -tcp-host=${TCP_HOST} \
    -tcp-port=${TCP_PORT}