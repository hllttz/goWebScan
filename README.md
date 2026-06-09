# goWebScan

goWebScan 是一个使用 Go 编写的轻量级命令行网络扫描器，设计上参考 nmap。当前重点是提供实用的 TCP/UDP 端口扫描、主机发现、服务识别、进度输出、结构化报告和优雅取消能力。

> 仅在你拥有或明确获得授权的系统和网络上使用本工具。

## 功能特性

- TCP Connect 扫描，默认不需要 root 或 raw socket 权限。
- 显式扫描模式：TCP connect（`-sT`）、SYN 模式（`-sS`）、UDP（`-sU`）。
- 使用 `-O` 进行轻量级 OS 指纹识别。
- 使用 TCP 探测进行主机发现，可用 `-Pn` 跳过。
- 端口状态：`open`、`closed`、`filtered`、`unreachable`、`unknown`。
- 每个结果包含 `reason` 字段，说明状态判断依据。
- 支持单目标、多目标、CIDR 和目标文件。
- 支持端口表达式：`22`、`22,80,443`、`1-1024`、`22,80,8000-8080`。
- 使用 `-p-` 扫描全部 TCP 端口。
- 使用 `top100` 或 `--top-ports N` 扫描常见端口。
- 使用 `--exclude-ports` 排除端口。
- 使用 `-sV` 进行轻量服务识别。
- 使用 `--version-intensity` 控制服务识别强度。
- 使用 `--open` 只显示开放端口。
- 支持文本、JSON、CSV 输出和输出到文件。
- 支持 Ctrl+C 优雅取消，并保留部分结果。

## 快速开始

从源码运行：

```bash
go run ./cmd/goscan scan 127.0.0.1 -Pn -p 22,80,443
```

构建 CLI：

```bash
go build -buildvcs=false -o goscan ./cmd/goscan
./goscan scan 127.0.0.1 -Pn -p 22,80,443
```

## CLI 用法

```bash
goscan scan <target...> [flags]
```

常用参数：

```text
-p, --ports          要扫描的端口，例如 22,80,443 或 1-1024
-p-                  扫描全部 TCP 端口，1-65535
--top-ports N        扫描最常见的 N 个 TCP 端口
--exclude-ports      排除端口，例如 25,137-139
-Pn                  跳过主机发现
-sT                  TCP connect 扫描，默认模式
-sS                  SYN 扫描模式，需要 raw socket 权限
-sU                  UDP 扫描模式
-sV                  启用服务版本识别
-O                   启用轻量级 OS 指纹识别
--version-intensity  服务识别强度：0=端口猜测，1=banner，2=轻量 probe
--open               只显示开放端口
--timeout            单次连接超时
--host-workers       最大并发目标数
--port-workers       每个目标最大并发端口扫描数
--json               输出 JSON
-oT                  写入普通文本结果
-oJ                  写入 JSON 结果
-oC                  写入 CSV 结果
--silent, --quiet    抑制进度输出和文件提示
--verbose            更频繁地输出进度
--no-color           禁用彩色输出
--banner-limit       保存 banner 的最大字节数
```

## 示例

```bash
# 扫描本机常见端口
goscan scan 127.0.0.1 -Pn -p 22,80,443

# 扫描 CIDR
goscan scan 192.168.1.0/24 -p 22,80,443 --host-workers 20 --port-workers 200

# 启用服务识别
goscan scan 127.0.0.1 -Pn -p 22,80,443,8080 -sV

# UDP 扫描
goscan scan 127.0.0.1 -Pn -sU -p 53,123,161

# SYN 模式和 OS 指纹识别
goscan scan 192.168.1.10 -sS -O -p 22,80,443

# 使用轻量主动 probe 识别 HTTP title、Redis PING 和 memcached version
goscan scan 127.0.0.1 -Pn -p 80,6379,11211 -sV --version-intensity 2

# JSON 输出
goscan scan 127.0.0.1 -Pn -p 1-1024 --json

# 全端口扫描，只显示开放端口
goscan scan 127.0.0.1 -Pn -p- --open

# 扫描 top 100 端口并排除噪声端口
goscan scan 192.168.1.10 --top-ports 100 --exclude-ports 25,137-139

# 同时写入多种输出格式
goscan scan 127.0.0.1 -Pn -p 22,80,443 -oT scan.txt -oJ scan.json -oC scan.csv

# 从目标文件读取
goscan scan targets.txt -p 22,80,443
```

## 文本输出示例

```text
Scan report for 127.0.0.1
Host is up, reason: discovery_skipped

PORT      STATE        SERVICE       VERSION            REASON
22/tcp    closed       -             -                  connection_refused
80/tcp    open         http          nginx              connect_succeeded
  status: 200
  server: nginx
443/tcp   filtered     https         -                  timeout

Summary:
  hosts total: 1
  hosts up: 1
  hosts down: 0
  hosts unknown: 0
  ports scanned: 3
  open: 1
  closed: 1
  filtered: 1
  unreachable: 0
  unknown: 0
  elapsed: 1.23s
```

## 服务识别

`-sV` 通过 detector 模块执行轻量服务识别。`--version-intensity` 控制交互强度：

```text
0  只根据端口猜测
1  只读取 banner，-sV 默认值
2  发送轻量 probe，例如 HTTP HEAD/GET、Redis PING、memcached version
```

当前 detector 包括：

- HTTP/HTTPS 元数据：status、Server、X-Powered-By、Location、title。
- TLS 证书基础信息：CN、SAN、Issuer、有效期、TLS version。
- SSH banner：protocol、product、version。
- FTP、SMTP、POP3、IMAP banner 签名。
- MySQL handshake、PostgreSQL 端口猜测、VNC banner。
- Redis PING 和 memcached version probe。
- unknown 服务 fallback，会保存截断后的 banner。

该实现保持保守和轻量，不兼容 NSE，也不会尝试防火墙绕过、隐蔽扫描或 IDS 规避。

## 高级扫描模式

`-sT` 是默认 TCP connect 模式，不需要额外权限。`-sU` 会发送小型 UDP probe，收到 UDP 响应时标记为 `open`；无响应通常标记为 filtered，因为 UDP 服务经常静默丢包。`-sS` 会检查 raw socket 权限，权限不足时返回 `raw_socket_unavailable`。当前 SYN 模式是保守 MVP：完成权限门禁和模式管线后，使用 TCP connect fallback，而不是完整手写 TCP 包状态机。

`-O` 会根据 TTL 和开放端口 hint 做轻量 OS 指纹识别。该结果是带置信度的启发式判断，不是确定性的 OS 识别。

## 输出格式

文本输出适合人工阅读。JSON 输出结构为：

```json
{
  "config": {},
  "hosts": [],
  "summary": {}
}
```

CSV 每个端口一行：

```text
host,ip,port,protocol,state,reason,service,product,version,banner,rtt_ms
```

`--json` 时 stdout 只输出 JSON，进度和日志写入 stderr。使用 `-oJ result.json` 时会写入 JSON 文件；加 `--quiet` 或 `--silent` 可抑制文件提示。

## 发布构建

常用开发命令：

```bash
make test
make build
make release
```

手动交叉编译：

```bash
GOOS=linux GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags="-s -w" -o dist/goscan-linux-amd64 ./cmd/goscan
GOOS=windows GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags="-s -w" -o dist/goscan-windows-amd64.exe ./cmd/goscan
```

发布产物示例：

```text
dist/goscan-v0.1.0-linux-amd64.tar.gz
dist/goscan-v0.1.0-windows-amd64.zip
dist/checksums.txt
```

## 模块

```text
github.com/hllttz/goWebScan
```

## 开发

运行测试：

```bash
go test ./...
go test -race ./...
```

部分测试会打开本地 TCP/UDP listener。如果沙箱阻止本地 socket，请在普通终端中运行测试。

## 项目结构

```text
cmd/goscan              CLI 入口
internal/app            扫描编排
internal/cli            CLI 参数、进度、Ctrl+C 处理
internal/discovery      主机发现
internal/scanner        TCP connect、SYN、UDP 扫描器和状态分类
internal/service        服务识别 detector
internal/osfingerprint  轻量 OS 指纹识别
internal/report         文本、JSON、CSV 输出
internal/target         目标和端口解析
pkg/goscan              共享结果类型
docs/architecture.md    架构说明
```

## 许可证

尚未选择许可证。
