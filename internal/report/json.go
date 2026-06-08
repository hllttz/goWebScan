package report

import (
	"encoding/json"
	"io"

	"github.com/hllttz/goWebScan/pkg/goscan"
)

func WriteJSON(w io.Writer, r goscan.Report) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(r)
}
