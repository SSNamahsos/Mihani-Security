package winapi

import (
	"bytes"
	"testing"
)

func TestProtectUnprotectRoundTrip(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	prot, err := ProtectData(key)
	if err != nil {
		t.Fatalf("protect: %v", err)
	}
	back, err := UnprotectData(prot)
	if err != nil {
		t.Fatalf("unprotect: %v", err)
	}
	if !bytes.Equal(key, back) {
		t.Fatal("roundtrip mismatch")
	}
}
