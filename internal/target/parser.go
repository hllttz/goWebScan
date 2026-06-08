package target

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"goscan/pkg/goscan"
)

func ParseTargets(ctx context.Context, inputs []string) ([]goscan.Target, error) {
	var targets []goscan.Target
	for _, input := range inputs {
		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}
		expanded, err := parseOne(ctx, input)
		if err != nil {
			return nil, err
		}
		targets = append(targets, expanded...)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets provided")
	}
	return targets, nil
}

func parseOne(ctx context.Context, input string) ([]goscan.Target, error) {
	if fileTargets, ok, err := parseTargetFile(ctx, input); ok || err != nil {
		return fileTargets, err
	}

	if ip := net.ParseIP(input); ip != nil {
		return []goscan.Target{{Input: input, Addresses: []net.IP{ip}}}, nil
	}

	if ip, ipnet, err := net.ParseCIDR(input); err == nil {
		return expandCIDR(input, ip, ipnet), nil
	}

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", input)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", input, err)
	}
	return []goscan.Target{{Input: input, Hostname: input, Addresses: ips}}, nil
}

func parseTargetFile(ctx context.Context, path string) ([]goscan.Target, bool, error) {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return nil, false, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, true, err
	}
	defer file.Close()

	var inputs []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		inputs = append(inputs, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, true, err
	}
	targets, err := ParseTargets(ctx, inputs)
	return targets, true, err
}

func expandCIDR(input string, ip net.IP, ipnet *net.IPNet) []goscan.Target {
	ip = ip.To4()
	if ip == nil {
		return []goscan.Target{{Input: input, Addresses: []net.IP{ip}}}
	}

	var targets []goscan.Target
	for current := append(net.IP(nil), ip.Mask(ipnet.Mask)...); ipnet.Contains(current); incIP(current) {
		addr := append(net.IP(nil), current...)
		targets = append(targets, goscan.Target{Input: input, Addresses: []net.IP{addr}})
	}
	if len(targets) > 2 {
		ones, bits := ipnet.Mask.Size()
		if bits == 32 && ones <= 30 {
			targets = targets[1 : len(targets)-1]
		}
	}
	return targets
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return
		}
	}
}
