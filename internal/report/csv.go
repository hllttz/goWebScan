package report

import (
	"encoding/csv"
	"io"
	"strconv"
	"strings"

	"github.com/hllttz/goWebScan/pkg/goscan"
)

func WriteCSV(w io.Writer, r goscan.Report) error {
	writer := csv.NewWriter(w)
	if err := writer.Write([]string{"host", "ip", "port", "protocol", "state", "reason", "service", "product", "version", "banner", "rtt_ms"}); err != nil {
		return err
	}
	for _, host := range r.HostResults() {
		address := ""
		if len(host.Target.Addresses) > 0 {
			address = host.Target.Addresses[0].String()
		}
		for _, port := range host.Ports {
			service, product, version, banner := "", "", "", ""
			if port.Service != nil {
				service = port.Service.Name
				product = port.Service.Product
				version = port.Service.Version
				banner = cleanCSVBanner(port.Service.Banner)
			}
			if err := writer.Write([]string{
				host.Target.Input,
				address,
				strconv.Itoa(int(port.Port.Number)),
				port.Port.Protocol,
				string(port.State),
				port.Reason,
				service,
				product,
				version,
				banner,
				strconv.FormatInt(port.Latency.Milliseconds(), 10),
			}); err != nil {
				return err
			}
		}
	}
	writer.Flush()
	return writer.Error()
}

func cleanCSVBanner(value string) string {
	return strings.Join(strings.Fields(value), " ")
}
