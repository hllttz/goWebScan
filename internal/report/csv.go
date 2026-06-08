package report

import (
	"encoding/csv"
	"io"
	"strconv"

	"github.com/hllttz/goWebScan/pkg/goscan"
)

func WriteCSV(w io.Writer, r goscan.Report) error {
	writer := csv.NewWriter(w)
	if err := writer.Write([]string{"host", "address", "port", "protocol", "state", "service", "product", "version", "reason", "latency_ns"}); err != nil {
		return err
	}
	for _, host := range r.Targets {
		address := ""
		if len(host.Target.Addresses) > 0 {
			address = host.Target.Addresses[0].String()
		}
		for _, port := range host.Ports {
			service, product, version := "", "", ""
			if port.Service != nil {
				service = port.Service.Name
				product = port.Service.Product
				version = port.Service.Version
			}
			if err := writer.Write([]string{
				host.Target.Input,
				address,
				strconv.Itoa(int(port.Port.Number)),
				port.Port.Protocol,
				string(port.State),
				service,
				product,
				version,
				port.Reason,
				strconv.FormatInt(int64(port.Latency), 10),
			}); err != nil {
				return err
			}
		}
	}
	writer.Flush()
	return writer.Error()
}
