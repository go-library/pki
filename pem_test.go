package pki

import (
	"crypto/x509"
	"reflect"
	"testing"
)

func SubtestPem(t *testing.T, algo algorithm) {
	var (
		err   error
		priv  interface{}
		priv2 interface{}
		data  []byte
	)
	priv, err = CreatePrivateKey(algo)
	if err != nil {
		t.Error(err)
	}

	data, err = EncodePEM(priv)
	if err != nil {
		t.Error(err)
	}

	priv2, err = DecodePEM(data)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(priv, priv2) {
		t.Error("priv != priv2")
	}

}
func TestEncodePEM(t *testing.T) {
	SubtestPem(t, RSA_1024)
	SubtestPem(t, ECDSA_P256)
	SubtestPem(t, DSA_L1024N160)

	if !testing.Short() {
		SubtestPem(t, RSA_2048)
		SubtestPem(t, ECDSA_P384)
		SubtestPem(t, ECDSA_P521)
		SubtestPem(t, DSA_L2048N224)
		SubtestPem(t, DSA_L2048N256)
	}

	var certBytes = []byte(`
-----BEGIN CERTIFICATE-----
MIIDQjCCAiqgAwIBAgIQBOXdqY4Jtp5Ku+c09ee6VjANBgkqhkiG9w0BAQsFADAg
MR4wHAYDVQQDExVDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMTYwOTEyMDc1NDMy
WhcNMjYwOTEwMDc1NDMyWjAgMR4wHAYDVQQDExVDZXJ0aWZpY2F0ZSBBdXRob3Jp
dHkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDIotIPjGTyYcMXga+W
m1GRTLiDj5z2U+JrvCz2ahgC6lb2gEi7MMOkV7PW+AFN2MoOSvYOaeRU7lxXuLlw
dPEnIfAVyemEx6DTQzvjOyGGlodjsK8J1oMYCAxqis0pYz9K+ItHgQU+82neyG67
3HWpZxPNX/rFMAaSZhQpMkNI/feTSZzYaUA8NFbNlIinnWP/bxCmbe37ae6y6QDE
5xK6n4ONgoOermUZGuDBSxUIhX+MCsJnXrqJSuZtBUUTyyVfLIWQpBe5v+CsmWvk
qo24X1QBP7uvKBUMCGoVV9807dYhGpYbIt9bHsTNo/w9AhGWR+gMtjSAo3yn6rw1
DHhbAgMBAAGjeDB2MA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggrBgEFBQcD
ATAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTRQGLvQAOsnYCiknRgsCZROe19
6jAfBgNVHSMEGDAWgBTRQGLvQAOsnYCiknRgsCZROe196jANBgkqhkiG9w0BAQsF
AAOCAQEAHYXXSnimyqeCSN6sI1RyrZkUGYiFkwnJCUn4pDcaND657FXV6R5ylaz/
uzLwsEcP0+ePYwSNXdbFdgtIK55T837UM9AFufnB9QW5pVirsZN24Z1n7ByYpxs4
A0312XKXMzkvQYjEUapnlGeiDIlm4FUSl3YVm/Rw/NfZYCmPRR27njD2XdWupKGL
6dSoBwJtN2SASm4TrdgI56XhGTjKsdTSFRYnusj2w/E2kojLQqIrehqld8G9XRLw
ATbCzNI0WaomcB3kbPXdlvWUh5ffS3j9nyeyv/8gQVA9f9mjvKkDqQxlHycS4zd0
lBzFPwcCYQ/HUd4DrVtUF1cqMNoXbQ==
-----END CERTIFICATE-----`)
	key, err := DecodePEM(certBytes)
	if err != nil {
		t.Error(err)
	}

	t.Log(key.(*x509.Certificate).SerialNumber)
}
