package target

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/hllttz/goWebScan/pkg/goscan"
)

var topPorts = []uint16{
	80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
	143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
	1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001,
	10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554,
	26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646,
	5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106,
	2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543,
	544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009,
	7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051,
	6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37,
}

type PortOptions struct {
	Expression   string
	TopPorts     int
	ExcludePorts string
}

func ParsePorts(expr string) ([]goscan.Port, error) {
	return ParsePortsWithOptions(PortOptions{Expression: expr})
}

func ParsePortsWithOptions(options PortOptions) ([]goscan.Port, error) {
	expr := strings.TrimSpace(options.Expression)
	if options.TopPorts > 0 {
		return selectPorts(topPorts, options.TopPorts, options.ExcludePorts)
	}
	expr = strings.TrimSpace(expr)
	if expr == "" {
		expr = "top100"
	}
	if expr == "top" || expr == "top100" {
		return selectPorts(topPorts, 100, options.ExcludePorts)
	}
	if expr == "-p-" || expr == "-" {
		return selectPorts(portRange(1, 65535), 65535, options.ExcludePorts)
	}

	seen := make(map[uint16]struct{})
	for _, part := range strings.Split(expr, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("empty port segment in %q", expr)
		}
		if strings.Contains(part, "-") {
			bounds := strings.Split(part, "-")
			if len(bounds) != 2 {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
			start, err := parsePortNumber(bounds[0])
			if err != nil {
				return nil, err
			}
			end, err := parsePortNumber(bounds[1])
			if err != nil {
				return nil, err
			}
			if start > end {
				return nil, fmt.Errorf("invalid descending port range %d-%d", start, end)
			}
			for p := start; p <= end; p++ {
				seen[p] = struct{}{}
				if p == 65535 {
					break
				}
			}
			continue
		}
		p, err := parsePortNumber(part)
		if err != nil {
			return nil, err
		}
		seen[p] = struct{}{}
	}

	nums := make([]uint16, 0, len(seen))
	for p := range seen {
		nums = append(nums, p)
	}
	sort.Slice(nums, func(i, j int) bool { return nums[i] < nums[j] })
	return applyExclusions(portsFromNumbers(nums), options.ExcludePorts)
}

func selectPorts(nums []uint16, limit int, excludeExpr string) ([]goscan.Port, error) {
	if limit <= 0 || limit > len(nums) {
		limit = len(nums)
	}
	selected := append([]uint16(nil), nums[:limit]...)
	sort.Slice(selected, func(i, j int) bool { return selected[i] < selected[j] })
	return applyExclusions(portsFromNumbers(selected), excludeExpr)
}

func applyExclusions(ports []goscan.Port, excludeExpr string) ([]goscan.Port, error) {
	excludeExpr = strings.TrimSpace(excludeExpr)
	if excludeExpr == "" {
		return ports, nil
	}
	excluded, err := parsePortSet(excludeExpr)
	if err != nil {
		return nil, fmt.Errorf("invalid exclude ports: %w", err)
	}
	out := make([]goscan.Port, 0, len(ports))
	for _, port := range ports {
		if _, ok := excluded[port.Number]; !ok {
			out = append(out, port)
		}
	}
	return out, nil
}

func parsePortSet(expr string) (map[uint16]struct{}, error) {
	seen := make(map[uint16]struct{})
	for _, part := range strings.Split(expr, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("empty port segment in %q", expr)
		}
		if strings.Contains(part, "-") {
			bounds := strings.Split(part, "-")
			if len(bounds) != 2 {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
			start, err := parsePortNumber(bounds[0])
			if err != nil {
				return nil, err
			}
			end, err := parsePortNumber(bounds[1])
			if err != nil {
				return nil, err
			}
			if start > end {
				return nil, fmt.Errorf("invalid descending port range %d-%d", start, end)
			}
			for p := start; p <= end; p++ {
				seen[p] = struct{}{}
				if p == 65535 {
					break
				}
			}
			continue
		}
		p, err := parsePortNumber(part)
		if err != nil {
			return nil, err
		}
		seen[p] = struct{}{}
	}
	return seen, nil
}

func portRange(start, end uint16) []uint16 {
	nums := make([]uint16, 0, int(end-start)+1)
	for p := start; p <= end; p++ {
		nums = append(nums, p)
		if p == 65535 {
			break
		}
	}
	return nums
}

func parsePortNumber(raw string) (uint16, error) {
	raw = strings.TrimSpace(raw)
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q", raw)
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("port out of range %d", n)
	}
	return uint16(n), nil
}

func portsFromNumbers(nums []uint16) []goscan.Port {
	ports := make([]goscan.Port, 0, len(nums))
	for _, n := range nums {
		ports = append(ports, goscan.Port{Number: n, Protocol: "tcp"})
	}
	return ports
}
