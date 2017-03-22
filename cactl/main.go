package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"github.com/go-library/pki"
	be "github.com/go-library/pki/backends/text"
	"github.com/go-library/xflag"
	"log"
	"os"
	"time"
)

var (
	fs = xflag.FlagSet{Name: "main", EnableCompletion: true}
)

func init() {
	log.SetFlags(log.Lshortfile)
}

func MakeCAKeyPair() (cakey interface{}, cacert *x509.Certificate, err error) {
	var ()
	cakey, err = pki.CreatePrivateKey(pki.RSA_2048)
	if err != nil {
		return nil, nil, err
	}

	cacert = new(x509.Certificate)
	cacert.PublicKey = pki.ToPublicKey(cakey)
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
	cacert.SubjectKeyId, err = pki.CreateHashSubjectKeyId(cacert.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	return cakey, cacert, nil
}

func CreateCertificate(cm *pki.CertManager, cname string) (cert *x509.Certificate, err error) {
	var (
		key interface{}
	)
	// create a key
	key, err = pki.CreatePrivateKey(pki.RSA_1024)
	if err != nil {
		return nil, err
	}

	// setting a cert data
	cert = new(x509.Certificate)
	cert.PublicKey = pki.ToPublicKey(key)
	cert.NotBefore = time.Now()
	cert.NotAfter = cert.NotBefore.Add(365 * 24 * time.Hour)

	cert.Subject = pkix.Name{
		CommonName: "Certiificate",
	}

	cert.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	cert.BasicConstraintsValid = true
	cert.SubjectKeyId, err = pki.CreateHashSubjectKeyId(cert.PublicKey)
	if err != nil {
		return nil, err
	}

	cert, err = cm.Sign(cert)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func main() {
	var (
		err     error
		backend pki.Backend
		cm      *pki.CertManager
		cert    *x509.Certificate
		isExist bool
	)

	defer func() {
		if err != nil {
			log.Println(err)
		}
	}()

	backend = be.Open("pkidb")

	if _, err = os.Stat("pkidb"); os.IsNotExist(err) {
		isExist = false
	} else {
		isExist = true
	}

	if isExist {
		// open
		cm, err = pki.OpenCertManager(backend)
		if err != nil {
		}
	} else {
		// create
		var (
			cakey  interface{}
			cacert *x509.Certificate
		)

		cakey, cacert, err = MakeCAKeyPair()
		if err != nil {
			os.Remove("pki.db")
			return
		}

		cm, err = pki.CreateCertManager(backend, cakey, cacert, true)
		if err != nil {
			os.Remove("pki.db")
			return
		}
	}

	cert, err = CreateCertificate(cm, "localhost.localdomain")
	if pem, err := pki.EncodePEM(cert); err == nil {
		fmt.Println(string(pem))
	}

	/*
		err = cm.VisitAll(func(cert *x509.Certificate) error {
			now := time.Now()
			if now.Before(cert.NotBefore) {
				fmt.Println("inactivated")
			}

			if now.After(cert.NotAfter) {
				fmt.Println("expired")
			}

			fmt.Printf("%s %s %s %s\n", cert.SerialNumber, cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02"), cert.Subject.CommonName)
			return nil
		})
	*/
	if err != nil {
		return
	}

	return
}
