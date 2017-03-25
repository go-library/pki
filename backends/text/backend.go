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
	err = os.MkdirAll(path.Dir(filename), 0755)
	if err != nil {
		return
	}
	return ioutil.ReadFile(filename)
}

func (b *TextBackend) writeFile(filename string, stream []byte, mode os.FileMode) (err error) {
	err = os.MkdirAll(path.Dir(filename), 0755)
	if err != nil {
		return
	}
	err = ioutil.WriteFile(filename, stream, mode)
	return
}

func (b *TextBackend) LookupCert(sn *big.Int) (matche string, err error) {
	matches, err := filepath.Glob(path.Join(b.BaseDir, FILE_CERTDIR, fmt.Sprintf("%x*", sn)))
	if len(matches) == 0 {
		err = fmt.Errorf("no matched certificate with %x", sn)
		return
	} else if len(matches) > 1 {
		err = fmt.Errorf("too many matched certificate with %x", sn)
		return
	}

	return matches[0], nil
}

func (b *TextBackend) GetNextSerialNumber() (serialNumber *big.Int, err error) {
	t, err := b.readFile(path.Join(b.BaseDir, FILE_NEXT_SERIAL))
	if os.IsNotExist(err) {
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

	err = b.writeFile(path.Join(b.BaseDir, FILE_NEXT_SERIAL), nextText, 0600)
	return
}

func (b *TextBackend) SetCAKeyPair(cakey interface{}, cacert *x509.Certificate) (err error) {
	cakeyPEM, err := pki.EncodePEM(cakey)
	if err != nil {
		return
	}

	err = b.writeFile(path.Join(b.BaseDir, FILE_CAKEY), cakeyPEM, 0600)
	if err != nil {
		return
	}

	cacertPEM, err := pki.EncodePEM(cacert)
	if err != nil {
		return
	}

	err = b.writeFile(path.Join(b.BaseDir, FILE_CACERT), cacertPEM, 0644)
	if err != nil {
		return
	}

	return
}

func (b *TextBackend) GetCAKeyPair() (cakey interface{}, cacert *x509.Certificate, err error) {
	cakeyPEM, err := b.readFile(path.Join(b.BaseDir, FILE_CAKEY))
	if err != nil {
		return
	}
	cakey, err = pki.DecodePEM(cakeyPEM)
	if err != nil {
		return
	}

	cacertPEM, err := b.readFile(path.Join(b.BaseDir, FILE_CACERT))
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

	err = b.writeFile(path.Join(b.BaseDir, FILE_CERTDIR, string(snText)+".pem"), certPEM, 0644)
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
	filename, err := b.LookupCert(serialNumber)
	if err != nil {
		return
	}

	certPEM, err := b.readFile(filename)
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
		terms := strings.Split(path.Base(matches[i]), ".")
		serialText := terms[0]
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
