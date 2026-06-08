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
