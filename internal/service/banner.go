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

	"github.com/hllttz/goWebScan/pkg/goscan"
)

type resultParser func(string, goscan.ServiceResult) goscan.ServiceResult

func dial(ctx context.Context, target goscan.Target, port goscan.Port, timeout time.Duration, tlsMode bool) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	address := net.JoinHostPort(hostName(target), strconv.Itoa(int(port.Number)))
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if tlsMode {
		return tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
			ServerName:         tlsServerName(target),
			InsecureSkipVerify: true,
		})
	}
	return dialer.DialContext(dialCtx, "tcp", address)
}

func readBanner(conn net.Conn, timeout time.Duration, limit int) string {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if limit <= 0 {
		limit = 512
	}
	buf := make([]byte, limit)
	n, _ := conn.Read(buf)
	if n == 0 {
		return ""
	}
	return sanitizeBanner(string(buf[:n]), limit)
}

func readHTTPHeaders(reader *bufio.Reader, limit int) []string {
	var lines []string
	for len(lines) < 40 {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimRight(line, "\r\n")
		lines = append(lines, line)
		if line == "" {
			break
		}
		if len(strings.Join(lines, "\n")) > limit {
			break
		}
	}
	return lines
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
	case 11211:
		return "memcached"
	default:
		return "unknown"
	}
}

func portGuess(port uint16) goscan.ServiceResult {
	name := serviceHint(port)
	confidence := 30
	reason := "port_guess"
	if name == "unknown" {
		confidence = 0
		reason = "unknown"
	}
	return goscan.ServiceResult{Name: name, Confidence: confidence, Reason: reason}
}

var sshBannerRE = regexp.MustCompile(`(?i)^(SSH-\d+\.\d+)-([A-Za-z]+)_?([^\s\r\n]*)`)
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
	{name: "memcached", product: "memcached", re: regexp.MustCompile(`(?i)^VERSION\s+([0-9.]+)`), confidence: 95},
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
	result.Banner = banner
	result.Confidence = 95
	result.Reason = "ssh_banner"
	matches := sshBannerRE.FindStringSubmatch(strings.TrimSpace(banner))
	if len(matches) >= 2 {
		result.Extra = setExtra(result.Extra, "protocol", matches[1])
	}
	if len(matches) >= 3 {
		result.Product = matches[2]
	}
	if len(matches) >= 4 {
		result.Version = strings.Trim(matches[3], "_-")
	}
	return result
}

func matchBannerSignatures(banner string, result goscan.ServiceResult) goscan.ServiceResult {
	if strings.TrimSpace(banner) == "" {
		return result
	}
	result.Banner = banner
	result.Reason = "banner"
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
	if target.Hostname != "" {
		return target.Hostname
	}
	return target.Input
}

func tlsServerName(target goscan.Target) string {
	if target.Hostname != "" {
		return target.Hostname
	}
	return ""
}

func sanitizeBanner(s string, limit int) string {
	s = truncate(s, limit)
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return r
		}
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, s)
}

func truncate(s string, limit int) string {
	if limit <= 0 || len(s) <= limit {
		return s
	}
	return s[:limit]
}

func setExtra(extra map[string]string, key, value string) map[string]string {
	if strings.TrimSpace(value) == "" {
		return extra
	}
	if extra == nil {
		extra = make(map[string]string)
	}
	extra[key] = value
	return extra
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("2006-01-02")
}

func statusFromLine(line string) string {
	fields := strings.Fields(line)
	if len(fields) >= 2 {
		return fields[1]
	}
	return ""
}

func titleFromBody(body string) string {
	re := regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	matches := re.FindStringSubmatch(body)
	if len(matches) < 2 {
		return ""
	}
	title := strings.Join(strings.Fields(matches[1]), " ")
	return truncate(title, 160)
}

func requestHost(target goscan.Target, port goscan.Port) string {
	host := target.Hostname
	if host == "" {
		host = hostName(target)
	}
	return fmt.Sprintf("%s:%d", host, port.Number)
}
