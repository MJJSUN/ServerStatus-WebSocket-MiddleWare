## 注意，该中间件不应该直接暴露在公网，/status统计接口未作鉴权和跨域限制，会导致客户端IP泄露。

本地访问/status会返回以下信息，connected_clients包含客户端IP

```
{"active_connections":0,"connected_clients":[],"authenticated":0}
```

## 正确食用方法：
使用防火墙或docker容器限制服务端口为127.0.0.1访问，然后使用Web服务器反向代理服务端口并对/status禁止访问。

同时配合Cloudflare CDN提升连接稳定性和安全性。

## Nginx示例
```
    # WebSocket Proxy Configuration
    location / {
        # Block access to /status endpoint
        if ($request_uri ~* "^/status") {
            return 403;
        }

        # WebSocket proxy settings
        proxy_pass http://localhost:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeout settings
        proxy_connect_timeout 7d;
        proxy_send_timeout 7d;
        proxy_read_timeout 7d;
    }

    # 显式禁止 /status 端点访问
    location /status {
        return 403;
    }
```

## 下载安装（以Linux为例）

```
git clone https://github.com/MJJSUN/ServerStatus-WebSocket-MiddleWare.git

cd ServerStatus-WebSocket-MiddleWare

go get github.com/gorilla/websocket

go build -o middleware_linux_amd64
```

## 运行
假设ServerStatus服务端口为6666，IP或域名为yourip
```
./middleware_linux_amd64 -ws-port=8080 -tcp-host=yourip -tcp-port=6666
```

## 在docker中运行
```
git clone https://github.com/MJJSUN/ServerStatus-WebSocket-MiddleWare.git

cd ServerStatus-WebSocket-MiddleWare

docker build -t middleware-app .
```

```
docker run -d --name serverstatus-middleware --restart always -e WS_PORT=8080 -e TCP_HOST="yourip" -e TCP_PORT=6666 -p 127.0.0.1:8080:8080 middleware-app:latest
```

## Usage

```
Usage of ./middleware_linux_amd64:
  -cert string
    	TLS certificate file (default "cert.pem")
  -key string
    	TLS private key file (default "key.pem")
  -log string
    	Log file path (default "middleware.log")
  -tcp-host string
    	Target TCP host (default "localhost")
  -tcp-port int
    	Target TCP port (default 35601)
  -tls
    	Enable TLS for WebSocket
  -verbose
    	Enable verbose logging
  -ws-port int
    	WebSocket server port (default 8080)
```

魔改版Websocket客户端请查看我的另一个项目

https://github.com/MJJSUN/ServerStatus-goclient

## TODO

安装脚本

