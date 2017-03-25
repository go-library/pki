package text

import (
	"github.com/go-library/pki"

	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const (
	FILE_NEXT_SERIAL = "next-serial.txt"
	FILE_CAKEY       = "cakey.pem"
	FILE_CACERT      = "cacert.pem"
	FILE_CERTDIR     = "certs"
)

type TextBackend struct {
	BaseDir string
}

func Open(baseDir string) *TextBackend {
	return &TextBackend{
		BaseDir: baseDir,
	}
}

func (b *TextBackend) readFile(filename string) (stream []byte, err error) {
	filepath := path.Join(b.BaseDir, filename)
	err = os.MkdirAll(path.Dir(filepath), 0755)
	if err != nil {
		return
	}

	return ioutil.ReadFile(filepath)
}

func (b *TextBackend) writeFile(filename string, stream []byte, mode os.FileMode) (err error) {
	filepath := path.Join(b.BaseDir, filename)
	err = os.MkdirAll(path.Dir(filepath), 0755)
	if err != nil {
		return
	}

	err = ioutil.WriteFile(filepath, stream, mode)
	return
}

func (b *TextBackend) GetNextSerialNumber() (serialNumber *big.Int, err error) {
	t, err := b.readFile(FILE_NEXT_SERIAL)
	if os.IsNotExist(err) {
		// Generate New SerialNumber
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, err = rand.Int(rand.Reader, serialNumberLimit)
	} else if err == nil {
		serialNumber = &big.Int{}
		err = serialNumber.UnmarshalText(t)
	}

	if err != nil {
		return
	}

	next := &big.Int{}
	next.Add(serialNumber, big.NewInt(1))

	nextText, err := next.MarshalText()
	if err != nil {
		return
	}

	err = b.writeFile(FILE_NEXT_SERIAL, nextText, 0600)
	return
}

func (b *TextBackend) SetCAKeyPair(cakey interface{}, cacert *x509.Certificate) (err error) {
	cakeyPEM, err := pki.EncodePEM(cakey)
	if err != nil {
		return
	}

	err = b.writeFile(FILE_CAKEY, cakeyPEM, 0600)
	if err != nil {
		return
	}

	cacertPEM, err := pki.EncodePEM(cacert)
	if err != nil {
		return
	}

	err = b.writeFile(FILE_CACERT, cacertPEM, 0644)
	if err != nil {
		return
	}

	return
}

func (b *TextBackend) GetCAKeyPair() (cakey interface{}, cacert *x509.Certificate, err error) {
	cakeyPEM, err := b.readFile(FILE_CAKEY)
	if err != nil {
		return
	}
	cakey, err = pki.DecodePEM(cakeyPEM)
	if err != nil {
		return
	}

	cacertPEM, err := b.readFile(FILE_CACERT)
	if err != nil {
		return
	}

	key, err := pki.DecodePEM(cacertPEM)
	if err != nil {
		return
	}

	var ok bool
	if cacert, ok = key.(*x509.Certificate); !ok {
		err = fmt.Errorf("cacert is invalid type")
	}

	return
}

func (b *TextBackend) AddCertificate(cert *x509.Certificate) (err error) {
	certPEM, err := pki.EncodePEM(cert)
	if err != nil {
		return
	}

	snText := fmt.Sprintf("%x", cert.SerialNumber)

	err = b.writeFile(path.Join(FILE_CERTDIR, string(snText)+".pem"), certPEM, 0644)
	if err != nil {
		return
	}

	return
}

func (b *TextBackend) DeleteCertificate(serialNumber *big.Int) (err error) {
	err = fmt.Errorf("DelCert unimplemented")
	return
}

func (b *TextBackend) Certificate(serialNumber *big.Int) (cert *x509.Certificate, revoked bool, err error) {
	filename := fmt.Sprintf("%x.pem", serialNumber)
	certPEM, err := b.readFile(path.Join(FILE_CERTDIR, filename))
	if err != nil {
		return
	}

	key, err := pki.DecodePEM(certPEM)
	if err != nil {
		return
	}

	cert = key.(*x509.Certificate)
	revoked = false
	return
}

func (b *TextBackend) RevokeCertificate(serialNumber *big.Int) (err error) {
	err = fmt.Errorf("RevokeCert unimplemented")
	return
}

func (b *TextBackend) RecoverCertificate(serialNumber *big.Int) (err error) {
	err = fmt.Errorf("RecoverCert unimplemented")
	return
}

func (b *TextBackend) Certificates(fn func(cert *x509.Certificate, revoked bool) (err error)) (err error) {
	matches, err := filepath.Glob(path.Join(b.BaseDir, FILE_CERTDIR, "*.pem"))
	if err != nil {
		return
	}

	for i := range matches {
		sn := &big.Int{}
		serialText := strings.TrimSuffix(path.Base(matches[i]), ".pem")
		fmt.Sscanf(serialText, "%x", sn)
		cert, revoked, err := b.Certificate(sn)
		if err != nil {
			return err
		}
		err = fn(cert, revoked)
		if err != nil {
			return err
		}
	}
	return
}
