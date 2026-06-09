package service

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/hllttz/goWebScan/pkg/goscan"
)

type HTTPDetector struct {
	TLS bool
}

func (d HTTPDetector) Name() string {
	if d.TLS {
		return "https"
	}
	return "http"
}

func (d HTTPDetector) MatchPort(port int) bool {
	if d.TLS {
		return port == 443 || port == 8443
	}
	return port == 80 || port == 8080 || port == 8000 || port == 8008 || port == 8888
}

func (d HTTPDetector) Detect(ctx context.Context, target goscan.Target, port goscan.Port, timeout time.Duration, bannerLimit int, intensity int) (goscan.ServiceResult, bool) {
	if intensity < IntensityProbe {
		return goscan.ServiceResult{}, false
	}
	conn, err := dial(ctx, target, port, timeout, d.TLS)
	if err != nil {
		return goscan.ServiceResult{}, false
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := fmt.Fprintf(conn, "HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: goscan\r\nConnection: close\r\n\r\n", requestHost(target, port)); err != nil {
		return goscan.ServiceResult{}, false
	}

	reader := bufio.NewReader(conn)
	lines := readHTTPHeaders(reader, bannerLimit)
	if len(lines) == 0 || !strings.HasPrefix(strings.ToUpper(lines[0]), "HTTP/") {
		return goscan.ServiceResult{}, false
	}

	result := goscan.ServiceResult{
		Name:       d.Name(),
		Confidence: 90,
		Banner:     sanitizeBanner(strings.Join(lines, "\n"), bannerLimit),
		Extra:      map[string]string{"status": statusFromLine(lines[0])},
		Reason:     "http_response",
	}
	if d.TLS {
		addTLSExtra(&result, conn)
	}
	for _, line := range lines[1:] {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "server":
			result.Extra["server"] = strings.TrimSpace(value)
			result.Product, result.Version = parseProductVersion(strings.TrimSpace(value))
		case "x-powered-by":
			result.Extra["x_powered_by"] = strings.TrimSpace(value)
		case "location":
			result.Extra["location"] = strings.TrimSpace(value)
		}
	}
	if title := d.getTitle(ctx, target, port, timeout, bannerLimit); title != "" {
		result.Extra["title"] = title
	}
	return result, true
}

func (d HTTPDetector) getTitle(ctx context.Context, target goscan.Target, port goscan.Port, timeout time.Duration, bannerLimit int) string {
	conn, err := dial(ctx, target, port, timeout, d.TLS)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	_, _ = fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: goscan\r\nConnection: close\r\n\r\n", requestHost(target, port))
	data, _ := io.ReadAll(io.LimitReader(conn, int64(max(bannerLimit, 4096))))
	return titleFromBody(string(data))
}

func tlsVersionName(version uint16) string {
	switch version {
	case 0x0301:
		return "TLS1.0"
	case 0x0302:
		return "TLS1.1"
	case 0x0303:
		return "TLS1.2"
	case 0x0304:
		return "TLS1.3"
	default:
		if version == 0 {
			return ""
		}
		return strconv.Itoa(int(version))
	}
}

func addTLSExtra(result *goscan.ServiceResult, conn interface{}) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}
	state := tlsConn.ConnectionState()
	result.Extra["tls_version"] = tlsVersionName(state.Version)
	result.Extra["tls_handshake"] = "true"
	if len(state.PeerCertificates) == 0 {
		return
	}
	cert := state.PeerCertificates[0]
	result.Extra["tls_cn"] = cert.Subject.CommonName
	result.Extra["tls_issuer"] = cert.Issuer.CommonName
	result.Extra["tls_not_before"] = formatTime(cert.NotBefore)
	result.Extra["tls_not_after"] = formatTime(cert.NotAfter)
	if len(cert.DNSNames) > 0 {
		result.Extra["tls_san"] = strings.Join(cert.DNSNames, ",")
	}
}
