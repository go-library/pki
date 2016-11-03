package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"testing"
	"time"
)

func TestCertManager(t *testing.T) {
	var (
		err    error
		cakey  interface{}
		cacert *x509.Certificate
		cm     *CertManager

		key  interface{}
		cert *x509.Certificate

		backend Backend
	)

	// create cakey
	cakey, err = CreatePrivateKey(RSA_1024)
	if err != nil {
		t.Fatal(err)
	}

	// setting cacert data
	cacert = new(x509.Certificate)
	cacert.PublicKey = ToPublicKey(cakey)
	cacert.NotBefore = time.Now()
	cacert.NotAfter = cacert.NotBefore.Add(3650 * 24 * time.Hour)
	cacert.Subject = pkix.Name{
		CommonName: "Certificate Authority",
	}
	cacert.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	cacert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	cacert.BasicConstraintsValid = true
	cacert.IsCA = true
	cacert.KeyUsage |= x509.KeyUsageCertSign
	cacert.SubjectKeyId, err = CreateHashSubjectKeyId(cacert.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	// set CA key-pair for cert-manager
	// create net cert-manager
	backend, err = NewBoltBackend("pkitest.db")
	cm, err = CreateCertManager(backend, cakey, cacert, true)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove("pkitest.db")
	if err != nil {
		t.Fatal(err)
	}

	// create a key
	key, err = CreatePrivateKey(RSA_1024)
	if err != nil {
		t.Fatal(err)
	}

	// setting a cert data
	cert = new(x509.Certificate)
	cert.PublicKey = ToPublicKey(key)
	cert.NotBefore = time.Now()
	cert.NotAfter = cert.NotBefore.Add(365 * 24 * time.Hour)

	cert.Subject = pkix.Name{
		CommonName: "Certiificate",
	}

	cert.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	cert.BasicConstraintsValid = true
	cert.SubjectKeyId, err = CreateHashSubjectKeyId(cert.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	cert, err = cm.Sign(cert)
	if err != nil {
		t.Fatal(err)
	}

	err = cm.VisitAll(func(cert *x509.Certificate) error {
		t.Log("cert:", cert.SerialNumber)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

}
