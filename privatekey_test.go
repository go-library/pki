package pki

import (
	"testing"
)

func SubtestPrivateKey(t *testing.T, algo algorithm) {
	_, err := CreatePrivateKey(algo)

	if err != nil {
		t.Error(err)
		return
	}

}

func TestCreatePrivateKey(t *testing.T) {
	SubtestPrivateKey(t, RSA_1024)
	SubtestPrivateKey(t, ECDSA_P256)
	SubtestPrivateKey(t, DSA_L1024N160)

	if !testing.Short() {
		SubtestPrivateKey(t, RSA_2048)
		SubtestPrivateKey(t, ECDSA_P384)
		SubtestPrivateKey(t, ECDSA_P521)
		SubtestPrivateKey(t, DSA_L2048N224)
		SubtestPrivateKey(t, DSA_L2048N256)
	}
}
