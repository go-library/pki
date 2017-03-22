package text_test

import (
	backend "github.com/go-library/pki/backends/text"

	"testing"
)

func TestBackend(t *testing.T) {
	b := backend.Open("pkidb")
	sn, err := b.GetNextSerialNumber()
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Serial Number:", sn)
}
