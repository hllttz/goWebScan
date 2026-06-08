package service

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"goscan/pkg/goscan"
)

type Identifier interface {
	Identify(ctx context.Context, target goscan.Target, port goscan.Port) (goscan.ServiceResult, error)
}

type BasicIdentifier struct {
	timeout     time.Duration
	bannerLimit int
}

func NewBasicIdentifier(timeout time.Duration, bannerLimit int) *BasicIdentifier {
	if bannerLimit <= 0 {
		bannerLimit = 1024
	}
	return &BasicIdentifier{timeout: timeout, bannerLimit: bannerLimit}
}

func (i *BasicIdentifier) Identify(ctx context.Context, target goscan.Target, port goscan.Port) (goscan.ServiceResult, error) {
	base := serviceHint(port.Number)
	result := goscan.ServiceResult{Name: base, Confidence: 30}
	if base == "" {
		result.Confidence = 0
	}

	switch port.Number {
	case 80, 8080, 8000, 8008, 8888:
		return i.identifyHTTP(ctx, target, port, false, result)
	case 443, 8443:
		return i.identifyHTTP(ctx, target, port, true, result)
	case 22:
		return i.identifyBanner(ctx, target, port, result, parseSSHBanner)
	case 21, 25, 110, 143:
		return i.identifyBanner(ctx, target, port, result, matchBannerSignatures)
	case 6379:
		return i.identifyWithProbe(ctx, target, port, result, "*1\r\n$4\r\nPING\r\n")
	default:
		identified, err := i.identifyBanner(ctx, target, port, result, matchBannerSignatures)
		if err != nil {
			return identified, err
		}
		if identified.Banner != "" && identified.Confidence > result.Confidence {
			return identified, nil
		}
		httpResult, err := i.identifyHTTP(ctx, target, port, false, identified)
		if err != nil {
			return identified, nil
		}
		if httpResult.Banner != "" && httpResult.Confidence > identified.Confidence {
			return httpResult, nil
		}
		return identified, nil
	}
}

func (i *BasicIdentifier) identifyHTTP(ctx context.Context, target goscan.Target, port goscan.Port, tlsMode bool, base goscan.ServiceResult) (goscan.ServiceResult, error) {
	conn, err := i.dial(ctx, target, port, tlsMode)
	if err != nil {
		return base, nil
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(i.timeout))
	_, _ = fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: goscan/0.1\r\n\r\n", hostName(target))

	reader := bufio.NewReader(conn)
	var lines []string
	for len(lines) < 20 {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimRight(line, "\r\n")
		lines = append(lines, line)
		if line == "" {
			break
		}
	}
	banner := truncate(strings.Join(lines, "\n"), i.bannerLimit)
	if banner == "" {
		return base, nil
	}

	result := base
	if tlsMode {
		result.Name = "https"
	} else {
		result.Name = "http"
	}
	result.Confidence = 85
	result.Banner = banner
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "server:") {
			product, version := parseProductVersion(strings.TrimSpace(line[len("server:"):]))
			result.Product = product
			result.Version = version
			result.Confidence = 90
			break
		}
	}
	return result, nil
}

func (i *BasicIdentifier) identifyBanner(ctx context.Context, target goscan.Target, port goscan.Port, base goscan.ServiceResult, parser func(string, goscan.ServiceResult) goscan.ServiceResult) (goscan.ServiceResult, error) {
	conn, err := i.dial(ctx, target, port, false)
	if err != nil {
		return base, nil
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(i.timeout))
	buf := make([]byte, i.bannerLimit)
	n, _ := conn.Read(buf)
	if n == 0 {
		return base, nil
	}

	base.Banner = truncate(string(buf[:n]), i.bannerLimit)
	base.Confidence = max(base.Confidence, 40)
	if parser != nil {
		base = parser(base.Banner, base)
	}
	return base, nil
}

func (i *BasicIdentifier) identifyWithProbe(ctx context.Context, target goscan.Target, port goscan.Port, base goscan.ServiceResult, probe string) (goscan.ServiceResult, error) {
	conn, err := i.dial(ctx, target, port, false)
	if err != nil {
		return base, nil
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(i.timeout))
	_, _ = conn.Write([]byte(probe))
	buf := make([]byte, i.bannerLimit)
	n, _ := conn.Read(buf)
	if n == 0 {
		return base, nil
	}
	base.Banner = truncate(string(buf[:n]), i.bannerLimit)
	base.Confidence = max(base.Confidence, 50)
	return matchBannerSignatures(base.Banner, base), nil
}

func (i *BasicIdentifier) dial(ctx context.Context, target goscan.Target, port goscan.Port, tlsMode bool) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: i.timeout}
	address := net.JoinHostPort(hostName(target), strconv.Itoa(int(port.Number)))
	dialCtx, cancel := context.WithTimeout(ctx, i.timeout)
	defer cancel()
	if tlsMode {
		return tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
			ServerName:         tlsServerName(target),
			InsecureSkipVerify: true,
		})
	}
	return dialer.DialContext(dialCtx, "tcp", address)
}

func serviceHint(port uint16) string {
	switch port {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 25:
		return "smtp"
	case 53:
		return "domain"
	case 80, 8080, 8000, 8008, 8888:
		return "http"
	case 110:
		return "pop3"
	case 139, 445:
		return "smb"
	case 143:
		return "imap"
	case 443, 8443:
		return "https"
	case 3306:
		return "mysql"
	case 3389:
		return "rdp"
	case 5432:
		return "postgresql"
	case 5900:
		return "vnc"
	case 6379:
		return "redis"
	default:
		return ""
	}
}

var sshBannerRE = regexp.MustCompile(`(?i)^SSH-\d+\.\d+-([A-Za-z]+)_?([^\s\r\n]*)`)
var signatureRules = []bannerSignature{
	{name: "ftp", product: "vsftpd", re: regexp.MustCompile(`(?i)vsftpd\s+([0-9][^\s\)]*)`), confidence: 95},
	{name: "ftp", product: "ProFTPD", re: regexp.MustCompile(`(?i)ProFTPD\s+([0-9][^\s\)]*)`), confidence: 95},
	{name: "ftp", product: "FileZilla Server", re: regexp.MustCompile(`(?i)FileZilla Server\s+([0-9][^\s]*)`), confidence: 95},
	{name: "smtp", product: "Postfix", re: regexp.MustCompile(`(?i)Postfix`), confidence: 90},
	{name: "smtp", product: "Exim", re: regexp.MustCompile(`(?i)Exim\s+([0-9][^\s]*)?`), confidence: 90},
	{name: "smtp", product: "Microsoft ESMTP", re: regexp.MustCompile(`(?i)Microsoft ESMTP MAIL Service`), confidence: 90},
	{name: "pop3", product: "Dovecot", re: regexp.MustCompile(`(?i)Dovecot.*ready`), confidence: 90},
	{name: "imap", product: "Dovecot", re: regexp.MustCompile(`(?i)Dovecot.*ready`), confidence: 90},
	{name: "mysql", product: "MySQL", re: regexp.MustCompile(`(?i)\x00?([0-9]+\.[0-9]+\.[0-9]+)[^\x00]*mysql`), confidence: 85},
	{name: "postgresql", product: "PostgreSQL", re: regexp.MustCompile(`(?i)postgresql`), confidence: 85},
	{name: "vnc", product: "RFB", re: regexp.MustCompile(`(?i)^RFB\s+([0-9.]+)`), confidence: 95},
	{name: "redis", product: "Redis", re: regexp.MustCompile(`(?i)(\+PONG|-NOAUTH|redis_version:([0-9.]+))`), confidence: 90},
	{name: "memcached", product: "memcached", re: regexp.MustCompile(`(?i)ERROR|CLIENT_ERROR|SERVER_ERROR`), confidence: 60},
	{name: "ssh", product: "OpenSSH", re: regexp.MustCompile(`(?i)^SSH-\d+\.\d+-OpenSSH[_-]([^\s\r\n]+)`), confidence: 95},
	{name: "http", product: "", re: regexp.MustCompile(`(?i)^HTTP/\d\.\d\s+\d+`), confidence: 85},
}

type bannerSignature struct {
	name       string
	product    string
	re         *regexp.Regexp
	confidence int
}

func parseSSHBanner(banner string, result goscan.ServiceResult) goscan.ServiceResult {
	result.Name = "ssh"
	result.Confidence = 95
	matches := sshBannerRE.FindStringSubmatch(strings.TrimSpace(banner))
	if len(matches) >= 2 {
		result.Product = matches[1]
	}
	if len(matches) >= 3 {
		result.Version = strings.Trim(matches[2], "_-")
	}
	return result
}

func matchBannerSignatures(banner string, result goscan.ServiceResult) goscan.ServiceResult {
	if strings.TrimSpace(banner) == "" {
		return result
	}
	result.Banner = banner
	for _, rule := range signatureRules {
		matches := rule.re.FindStringSubmatch(banner)
		if len(matches) == 0 {
			continue
		}
		result.Name = rule.name
		if rule.product != "" {
			result.Product = rule.product
		}
		result.Confidence = max(result.Confidence, rule.confidence)
		for i := 1; i < len(matches); i++ {
			if strings.TrimSpace(matches[i]) != "" && looksLikeVersion(matches[i]) {
				result.Version = strings.Trim(matches[i], " _-")
				break
			}
		}
		return result
	}
	return result
}

func parseProductVersion(raw string) (string, string) {
	first := strings.Fields(raw)
	if len(first) == 0 {
		return "", ""
	}
	parts := strings.SplitN(first[0], "/", 2)
	if len(parts) == 1 {
		return parts[0], ""
	}
	return parts[0], parts[1]
}

func looksLikeVersion(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	return value[0] >= '0' && value[0] <= '9'
}

func hostName(target goscan.Target) string {
	if len(target.Addresses) > 0 {
		return target.Addresses[0].String()
	}
	return target.Hostname
}

func tlsServerName(target goscan.Target) string {
	if target.Hostname != "" {
		return target.Hostname
	}
	return ""
}

func truncate(s string, limit int) string {
	if limit <= 0 || len(s) <= limit {
		return s
	}
	return s[:limit]
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
