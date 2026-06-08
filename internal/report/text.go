package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/hllttz/goWebScan/pkg/goscan"
)

func WriteText(w io.Writer, r goscan.Report) error {
	if _, err := fmt.Fprintf(w, "Starting GoScan 0.1 at %s\n", time.Now().Format("2006-01-02 15:04 MST")); err != nil {
		return err
	}
	for _, target := range r.Targets {
		if _, err := fmt.Fprintf(w, "GoScan scan report for %s\n", targetName(target)); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "Host is %s (%s).\n", target.Status, reasonText(target.Reason)); err != nil {
			return err
		}
		if target.Error != "" {
			if _, err := fmt.Fprintf(w, "Host error: %s\n", target.Error); err != nil {
				return err
			}
		}
		sort.Slice(target.Ports, func(i, j int) bool {
			return target.Ports[i].Port.Number < target.Ports[j].Port.Number
		})
		if len(target.Ports) == 0 {
			if _, err := fmt.Fprintln(w, "No ports scanned."); err != nil {
				return err
			}
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
			continue
		}
		if _, err := fmt.Fprintln(w, "PORT      STATE        SERVICE       VERSION            REASON"); err != nil {
			return err
		}
		for _, port := range target.Ports {
			service, version := serviceColumns(port)
			if _, err := fmt.Fprintf(w, "%-9s %-12s %-13s %-18s %s\n",
				fmt.Sprintf("%d/%s", port.Port.Number, port.Port.Protocol),
				port.State,
				service,
				version,
				reasonText(port.Reason),
			); err != nil {
				return err
			}
		}
		summary := summarizePorts(target.Ports)
		if _, err := fmt.Fprintf(w, "Port summary: %d open, %d closed, %d filtered, %d unreachable, %d unknown\n",
			summary.open, summary.closed, summary.filtered, summary.unreachable, summary.unknown); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "GoScan done: %d IP address(es) scanned\n", len(r.Targets)); err != nil {
		return err
	}
	return nil
}

func targetName(target goscan.HostResult) string {
	if len(target.Target.Addresses) > 0 {
		return fmt.Sprintf("%s (%s)", target.Target.Input, target.Target.Addresses[0])
	}
	return target.Target.Input
}

func serviceColumns(port goscan.PortResult) (string, string) {
	if port.Service == nil {
		return "-", "-"
	}
	service := port.Service.Name
	if service == "" {
		service = "-"
	}
	version := strings.TrimSpace(strings.Join(nonEmpty(port.Service.Product, port.Service.Version), " "))
	if version == "" {
		version = "-"
	}
	return service, version
}

func nonEmpty(values ...string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func reasonText(reason string) string {
	if reason == "" {
		return "-"
	}
	return reason
}

type portSummary struct {
	open        int
	closed      int
	filtered    int
	unreachable int
	unknown     int
}

func summarizePorts(ports []goscan.PortResult) portSummary {
	var summary portSummary
	for _, port := range ports {
		switch port.State {
		case goscan.PortOpen:
			summary.open++
		case goscan.PortClosed:
			summary.closed++
		case goscan.PortFiltered:
			summary.filtered++
		case goscan.PortUnreachable:
			summary.unreachable++
		default:
			summary.unknown++
		}
	}
	return summary
}
