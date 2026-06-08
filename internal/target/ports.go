package target

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"goscan/pkg/goscan"
)

var topPorts = []uint16{21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080}

func ParsePorts(expr string) ([]goscan.Port, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		expr = "top"
	}
	if expr == "top" || expr == "top100" {
		return portsFromNumbers(topPorts), nil
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
	return portsFromNumbers(nums), nil
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
