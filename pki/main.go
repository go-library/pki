package main

import (
	"github.com/go-library/pki"
	be "github.com/go-library/pki/backends/text"

	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"log"
	"os"
	"time"
)

var (
	cn = flag.String("cn", "", "subject common name")
)

func init() {
	log.SetFlags(log.Lshortfile)
}

func MakeCAKeyPair() (cakey interface{}, cacert *x509.Certificate, err error) {
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
		return
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
		return
	}

	// setting a cert data
	cert = new(x509.Certificate)
	cert.PublicKey = pki.ToPublicKey(key)
	cert.NotBefore = time.Now()
	cert.NotAfter = cert.NotBefore.Add(365 * 24 * time.Hour)

	cert.Subject = pkix.Name{
		CommonName: cname,
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
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `
Usage:
  pki [ OPTIONS ] COMMAND { ARGS }

COMMANDS:
  build-ca

  create COMMON-NAME

  revoke SERIAL-NUMBER

  recover SERIAL-NUMBER

  list

  cacert
	
  crl

COPTIONS:
`)
		flag.PrintDefaults()
	}

	flag.Parse()
	args := flag.Args()

	if len(args) == 0 {
		flag.Usage()
		log.Fatal("command required")
	}

	backend = be.Open("CA")

	if args[0] != "build-ca" {
		cm, err = pki.OpenCertManager(backend)
		if err != nil {
			log.Fatal(err)
		}
	}

	switch args[0] {

	case "build-ca":
		// create
		var (
			cakey  interface{}
			cacert *x509.Certificate
		)

		cakey, cacert, err = MakeCAKeyPair()
		if err != nil {
			log.Fatal(err)
		}

		cm, err = pki.CreateCertManager(backend, cakey, cacert, true)
		if err != nil {
			log.Fatal(err)
		}

	case "list":
		now := time.Now()

		err = cm.Certificates(func(cert *x509.Certificate, revoked bool) (err error) {
			if now.Before(cert.NotBefore) {
				fmt.Println("inactivated")
			}

			if now.After(cert.NotAfter) {
				fmt.Println("expired")
			}

			fmt.Printf("%x %s %s %s\n",
				cert.SerialNumber,
				cert.NotBefore.Format("2006-01-02"),
				cert.NotAfter.Format("2006-01-02"),
				cert.Subject.CommonName)

			return nil
		})
		if err != nil {
			log.Fatal(err)
		}

	case "create":
		cert, err = CreateCertificate(cm, "localhost.localdomain")
		if pem, err := pki.EncodePEM(cert); err == nil {
			fmt.Println(string(pem))
		}

	default:
		flag.Usage()
		log.Fatalf("unkown command: %s", args[0])
	}

	return
}
