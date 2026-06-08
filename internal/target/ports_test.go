package target

import "testing"

func TestParsePortsMixedExpression(t *testing.T) {
	ports, err := ParsePorts("80,22,8000-8002,22")
	if err != nil {
		t.Fatal(err)
	}
	got := make([]uint16, 0, len(ports))
	for _, port := range ports {
		got = append(got, port.Number)
	}
	want := []uint16{22, 80, 8000, 8001, 8002}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestParsePortsRejectsInvalidPort(t *testing.T) {
	if _, err := ParsePorts("0"); err == nil {
		t.Fatal("expected error")
	}
}

func TestParsePortsDashPScansAllPorts(t *testing.T) {
	ports, err := ParsePorts("-p-")
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 65535 {
		t.Fatalf("got %d ports, want 65535", len(ports))
	}
	if ports[0].Number != 1 || ports[len(ports)-1].Number != 65535 {
		t.Fatalf("range = %d..%d", ports[0].Number, ports[len(ports)-1].Number)
	}
}

func TestParsePortsTopPortsAndExclude(t *testing.T) {
	ports, err := ParsePortsWithOptions(PortOptions{TopPorts: 5, ExcludePorts: "80,443"})
	if err != nil {
		t.Fatal(err)
	}
	got := make([]uint16, 0, len(ports))
	for _, port := range ports {
		got = append(got, port.Number)
	}
	want := []uint16{21, 22, 23}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestTop100MeansOneHundredPorts(t *testing.T) {
	ports, err := ParsePorts("top100")
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 100 {
		t.Fatalf("got %d ports, want 100", len(ports))
	}
}
