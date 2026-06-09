# goscan v0.3 服务识别增强版本建议

## 1. 版本目标

v0.3 的目标是增强 `-sV` 服务识别能力，并把服务识别从扫描主流程中拆出来，形成可扩展的 detector 架构。

建议版本定位：

> v0.3 是服务识别增强版本，重点提升 HTTP、SSH、FTP、SMTP、数据库、中间件等常见服务的识别准确性，同时保持轻量、普通权限、低侵入。

## 2. 核心目标

v0.3 重点完成：

- 新增 `ServiceDetector` 接口
- 拆分不同服务 detector
- 支持 banner 保存
- 支持 version 字段
- 支持 `--version-intensity`
- 增强 HTTP / HTTPS 识别
- 增强 SSH / FTP / SMTP banner 识别
- 增强 Redis / memcached / MySQL / PostgreSQL 识别
- 增加 TLS 证书基础信息
- 增加 HTTP title 抓取
- 增加服务识别测试

## 3. 不做内容

v0.3 不做：

- 漏洞扫描
- 爆破
- 指纹库大规模匹配
- NSE 类脚本引擎
- 主动高风险 payload
- Web 目录扫描
- SQL 注入检测
- 弱口令检测

原因：v0.3 只做服务识别，不做安全检测或漏洞利用。

## 4. 模块结构建议

建议新增或完善：

```text
internal/service/
  detector.go
  result.go
  registry.go
  banner.go
  port_guess.go
  http.go
  https.go
  tls.go
  ssh.go
  ftp.go
  smtp.go
  pop3.go
  imap.go
  mysql.go
  postgres.go
  redis.go
  memcached.go
  vnc.go
  unknown.go
```

## 5. 核心接口设计

### 5.1 ServiceResult

```go
type ServiceResult struct {
	Service string `json:"service,omitempty"`
	Product string `json:"product,omitempty"`
	Version string `json:"version,omitempty"`
	Banner  string `json:"banner,omitempty"`
	Extra   map[string]string `json:"extra,omitempty"`
	Reason  string `json:"reason,omitempty"`
}
```

说明：

- `Service`：服务类型，例如 `http`、`ssh`、`redis`
- `Product`：产品名，例如 `nginx`、`OpenSSH`
- `Version`：版本号，例如 `8.9`
- `Banner`：原始 banner
- `Extra`：扩展信息，例如 HTTP title、TLS CN
- `Reason`：识别依据

### 5.2 ServiceDetector

```go
type ServiceDetector interface {
	Name() string
	MatchPort(port int) bool
	Detect(ctx context.Context, host string, port int, timeout time.Duration) (ServiceResult, bool)
}
```

### 5.3 Registry

```go
type Registry struct {
	detectors []ServiceDetector
}

func NewDefaultRegistry() *Registry

func (r *Registry) Detect(ctx context.Context, host string, port int, timeout time.Duration) ServiceResult
```

## 6. 识别流程

建议顺序：

```text
1. 根据端口做初步猜测
2. 如果开启 -sV，则进入 detector 流程
3. 优先执行与端口匹配的 detector
4. 如果失败，执行通用 banner detector
5. 如果仍失败，返回端口猜测结果
```

示例：

```text
22/tcp -> SSHDetector -> 读取 SSH banner -> ssh / OpenSSH / 8.9
80/tcp -> HTTPDetector -> HEAD / GET -> http / nginx / title
443/tcp -> TLSDetector + HTTPSDetector -> 证书 + HTTPS header
6379/tcp -> RedisDetector -> PING -> +PONG
11211/tcp -> MemcachedDetector -> version -> VERSION x.x.x
```

## 7. version intensity 设计

建议新增参数：

```bash
--version-intensity 0
--version-intensity 1
--version-intensity 2
```

含义：

```text
0：只根据端口猜测，不主动探测
1：读取 banner，低交互
2：发送轻量 probe，例如 HTTP HEAD、Redis PING、memcached version
```

默认建议：

```text
-sV 默认 --version-intensity 1
```

如果用户显式传：

```bash
-sV --version-intensity 2
```

才发送主动 probe。

## 8. HTTP 识别建议

### 8.1 探测方式

HTTP 端口建议发送：

```text
HEAD / HTTP/1.1
Host: target
User-Agent: goscan
Connection: close
```

如果 HEAD 失败，可选 GET：

```text
GET / HTTP/1.1
Host: target
User-Agent: goscan
Connection: close
```

### 8.2 提取字段

建议提取：

- HTTP status code
- Server header
- X-Powered-By
- title
- redirect location

### 8.3 结果示例

```text
80/tcp open http nginx
  title: Example Domain
  status: 200
```

### 8.4 Extra 示例

```go
Extra: map[string]string{
	"status": "200",
	"server": "nginx",
	"title": "Example Domain",
}
```

## 9. HTTPS / TLS 识别建议

### 9.1 TLS 信息

建议提取：

- TLS 握手是否成功
- 证书 CN
- SAN
- Issuer
- NotBefore
- NotAfter
- TLS version

### 9.2 输出示例

```text
443/tcp open https nginx
  tls_cn: example.com
  tls_expires: 2026-12-01
  title: Example Domain
```

### 9.3 注意事项

- 不要校验证书失败就认为服务不是 HTTPS
- 自签名证书也应记录
- 证书过期可以展示，但不要做漏洞结论

## 10. SSH 识别建议

### 10.1 读取 banner

SSH 服务一般连接后会返回：

```text
SSH-2.0-OpenSSH_8.9
```

### 10.2 提取字段

- protocol：SSH-2.0
- product：OpenSSH
- version：8.9

### 10.3 输出

```text
22/tcp open ssh OpenSSH 8.9
```

## 11. FTP / SMTP / POP3 / IMAP 识别建议

这些服务通常有 banner。

建议读取首行：

```text
FTP: 220 ...
SMTP: 220 ...
POP3: +OK ...
IMAP: * OK ...
```

输出：

```text
21/tcp open ftp vsftpd 3.0.3
25/tcp open smtp Postfix
110/tcp open pop3
143/tcp open imap
```

## 12. Redis 识别建议

version intensity 2 时发送：

```text
PING\r\n
```

预期：

```text
+PONG
```

也可发送 RESP 格式：

```text
*1\r\n$4\r\nPING\r\n
```

输出：

```text
6379/tcp open redis
```

注意：

- 只做 PING
- 不做 AUTH
- 不做 CONFIG
- 不做 INFO，避免输出敏感信息

## 13. memcached 识别建议

version intensity 2 时发送：

```text
version\r\n
```

预期：

```text
VERSION 1.6.XX
```

输出：

```text
11211/tcp open memcached 1.6.XX
```

## 14. MySQL 识别建议

MySQL 通常连接后会返回 handshake。

可提取：

- protocol version
- server version

输出：

```text
3306/tcp open mysql 8.0.XX
```

只读取握手，不发送登录包。

## 15. PostgreSQL 识别建议

PostgreSQL 不一定直接返回 banner。

可以考虑发送 SSLRequest，但要保持轻量。

建议 v0.3 最小实现：

- 端口 5432 默认猜测为 PostgreSQL
- 如有响应则记录 reason
- 不做认证、不做枚举

输出：

```text
5432/tcp open postgresql
```

## 16. VNC 识别建议

VNC 通常返回：

```text
RFB 003.008
```

输出：

```text
5900/tcp open vnc RFB 003.008
```

## 17. unknown 服务处理

如果端口开放但无法识别：

```text
9000/tcp open unknown
```

如果有 banner：

```text
9000/tcp open unknown
  banner: ...
```

注意 banner 输出要做截断，防止控制台污染。

建议：

```text
banner 最大保存 512 bytes
文本输出最大展示 120 字符
JSON 保留完整截断后的 banner
```

## 18. 输出字段增强

`PortResult` 中建议保留：

```go
Service string `json:"service,omitempty"`
Product string `json:"product,omitempty"`
Version string `json:"version,omitempty"`
Banner  string `json:"banner,omitempty"`
Extra   map[string]string `json:"extra,omitempty"`
```

CSV 字段建议：

```text
host,ip,port,protocol,state,reason,service,product,version,banner,rtt_ms
```

## 19. 测试建议

### 19.1 单元测试

```text
internal/service/http_test.go
internal/service/ssh_test.go
internal/service/redis_test.go
internal/service/memcached_test.go
internal/service/mysql_test.go
internal/service/banner_test.go
```

### 19.2 本地 fake server

用 Go 在测试中启动临时 TCP 服务：

```text
fake SSH server -> 返回 SSH-2.0-OpenSSH_8.9
fake FTP server -> 返回 220 vsftpd 3.0.3
fake VNC server -> 返回 RFB 003.008
fake Redis server -> 接收 PING 返回 +PONG
```

### 19.3 HTTP 测试

使用 `httptest.Server`。

验证：

- status code
- Server header
- title
- service=http

### 19.4 TLS 测试

使用 `httptest.NewTLSServer`。

验证：

- service=https
- TLS 握手成功
- 证书信息存在

## 20. v0.3 推荐提交拆分

### Commit 1

```text
feat: 新增服务识别结果模型
```

内容：

- `ServiceResult`
- service extra 字段
- PortResult 扩展字段

### Commit 2

```text
feat: 新增服务识别 detector 架构
```

内容：

- `ServiceDetector`
- `Registry`
- 默认 detector 注册

### Commit 3

```text
feat: 增强 HTTP 和 HTTPS 服务识别
```

内容：

- HTTP HEAD / GET
- Server header
- title
- TLS 基础信息

### Commit 4

```text
feat: 增强常见 banner 服务识别
```

内容：

- SSH
- FTP
- SMTP
- POP3
- IMAP
- VNC

### Commit 5

```text
feat: 增强数据库和中间件服务识别
```

内容：

- MySQL
- PostgreSQL
- Redis
- memcached

### Commit 6

```text
feat: 支持服务识别强度参数
```

内容：

- `--version-intensity`
- intensity 0 / 1 / 2 行为
- README 说明

### Commit 7

```text
test: 补充服务识别测试
```

内容：

- fake TCP server
- HTTP test server
- TLS test server
- banner matching tests

## 21. v0.3 验收命令

```bash
go test ./...

go test -race ./...

go run ./cmd/goscan scan 127.0.0.1 -Pn -p 22 -sV

go run ./cmd/goscan scan 127.0.0.1 -Pn -p 80 -sV

go run ./cmd/goscan scan 127.0.0.1 -Pn -p 443 -sV

go run ./cmd/goscan scan 127.0.0.1 -Pn -p 6379 -sV --version-intensity 2

go run ./cmd/goscan scan 127.0.0.1 -Pn -p 11211 -sV --version-intensity 2

go run ./cmd/goscan scan 127.0.0.1 -Pn -p 1-1000 -sV --open
```

## 22. v0.3 完成标准

v0.3 完成后应该满足：

- `-sV` 逻辑独立于扫描主流程
- 每类服务 detector 独立文件
- HTTP 能识别 status、server、title
- HTTPS 能识别 TLS 基础信息
- SSH / FTP / SMTP 等 banner 服务能识别
- Redis / memcached 可以通过轻量 probe 识别
- MySQL 可以读取 handshake
- 未识别服务不会影响扫描结果
- 服务识别超时不会卡住端口扫描
- 有完整服务识别测试
