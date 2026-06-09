package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/hllttz/goWebScan/pkg/goscan"
)

func WriteText(w io.Writer, r goscan.Report) error {
	for _, target := range r.HostResults() {
		if _, err := fmt.Fprintf(w, "Scan report for %s\n", targetName(target)); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "Host is %s, reason: %s\n", target.Status, reasonText(target.Reason)); err != nil {
			return err
		}
		if target.Error != "" {
			if _, err := fmt.Fprintf(w, "Host error: %s\n", target.Error); err != nil {
				return err
			}
		}
		if len(target.Ports) == 0 {
			if _, err := fmt.Fprintln(w, "No ports scanned."); err != nil {
				return err
			}
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
			continue
		}
		if _, err := fmt.Fprintln(w); err != nil {
			return err
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
			for _, detail := range serviceDetails(port) {
				if _, err := fmt.Fprintf(w, "  %s\n", detail); err != nil {
					return err
				}
			}
		}
		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
	}
	return WriteSummary(w, r.Summary)
}

func serviceDetails(port goscan.PortResult) []string {
	if port.Service == nil {
		return nil
	}
	var details []string
	for _, key := range []string{"status", "server", "title", "location", "tls_cn", "tls_issuer", "tls_not_after", "tls_version"} {
		if value := port.Service.Extra[key]; value != "" {
			details = append(details, fmt.Sprintf("%s: %s", key, value))
		}
	}
	if port.Service.Banner != "" {
		banner := strings.Join(strings.Fields(port.Service.Banner), " ")
		details = append(details, fmt.Sprintf("banner: %s", truncateText(banner, 120)))
	}
	return details
}

func truncateText(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

func targetName(target goscan.HostResult) string {
	if len(target.Target.Addresses) > 0 {
		return target.Target.Addresses[0].String()
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

func WriteSummary(w io.Writer, summary goscan.ScanSummary) error {
	if _, err := fmt.Fprintln(w, "Summary:"); err != nil {
		return err
	}
	if summary.Canceled {
		if _, err := fmt.Fprintln(w, "  status: canceled"); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "  scanned before cancel: %d ports\n", summary.PortsScanned); err != nil {
			return err
		}
	}
	lines := []struct {
		name  string
		value any
	}{
		{"hosts total", summary.HostsTotal},
		{"hosts up", summary.HostsUp},
		{"hosts down", summary.HostsDown},
		{"hosts unknown", summary.HostsUnknown},
		{"ports scanned", summary.PortsScanned},
		{"open", summary.PortsOpen},
		{"closed", summary.PortsClosed},
		{"filtered", summary.PortsFiltered},
		{"unreachable", summary.PortsUnreachable},
		{"unknown", summary.PortsUnknown},
		{"elapsed", elapsedText(summary)},
	}
	for _, line := range lines {
		if _, err := fmt.Fprintf(w, "  %s: %v\n", line.name, line.value); err != nil {
			return err
		}
	}
	return nil
}

func elapsedText(summary goscan.ScanSummary) string {
	if summary.ElapsedMs <= 0 && !summary.StartedAt.IsZero() && !summary.FinishedAt.IsZero() {
		return summary.FinishedAt.Sub(summary.StartedAt).Round(time.Millisecond).String()
	}
	return (time.Duration(summary.ElapsedMs) * time.Millisecond).String()
}
