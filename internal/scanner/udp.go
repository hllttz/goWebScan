package scanner

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/hllttz/goWebScan/pkg/goscan"
)

type UDPScanner struct {
	timeout time.Duration
}

func NewUDPScanner(timeout time.Duration) *UDPScanner {
	return &UDPScanner{timeout: timeout}
}

func (s *UDPScanner) Scan(ctx context.Context, target goscan.Target, port goscan.Port) (goscan.PortResult, error) {
	start := time.Now()
	address := net.JoinHostPort(firstAddress(target), strconv.Itoa(int(port.Number)))
	dialer := net.Dialer{Timeout: s.timeout}
	scanCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	conn, err := dialer.DialContext(scanCtx, "udp", address)
	latency := time.Since(start)
	result := goscan.PortResult{Port: port, Latency: latency}
	if err != nil {
		state, reason := ClassifyDialError(err)
		result.State = state
		result.Reason = reason
		result.Error = err.Error()
		return result, nil
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(s.timeout))
	_, writeErr := conn.Write(udpProbe(port.Number))
	if writeErr != nil {
		state, reason := ClassifyDialError(writeErr)
		result.State = state
		result.Reason = reason
		result.Error = writeErr.Error()
		return result, nil
	}
	buf := make([]byte, 512)
	n, readErr := conn.Read(buf)
	result.Latency = time.Since(start)
	if readErr == nil && n > 0 {
		result.State = goscan.PortOpen
		result.Reason = "udp_response"
		return result, nil
	}
	if readErr != nil {
		state, reason := ClassifyDialError(readErr)
		if state == goscan.PortFiltered && reason == "timeout" {
			result.State = goscan.PortFiltered
			result.Reason = "no_udp_response"
			result.Error = readErr.Error()
			return result, nil
		}
		result.State = state
		result.Reason = reason
		result.Error = readErr.Error()
		return result, nil
	}
	result.State = goscan.PortUnknown
	result.Reason = "empty_udp_response"
	return result, nil
}

func udpProbe(port uint16) []byte {
	switch port {
	case 53:
		return []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	case 123:
		return []byte{0x1b}
	case 161:
		return []byte{0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c', 0xa0, 0x19, 0x02, 0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00}
	default:
		return []byte{0}
	}
}
