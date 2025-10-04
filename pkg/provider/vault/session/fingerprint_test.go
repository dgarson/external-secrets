package session

import "testing"

func TestFingerprintDeterminism(t *testing.T) {
	data := map[string]string{"a": "1", "b": "2"}
	first := Fingerprint(data, "extra")
	second := Fingerprint(data, "extra")
	if first != second {
		t.Fatalf("expected deterministic fingerprint, got %s and %s", first, second)
	}

	third := Fingerprint(data, "different")
	if first == third {
		t.Fatalf("expected different fingerprint when extras change")
	}
}
