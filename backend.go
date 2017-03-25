package pki

import (
	"crypto/x509"
	"math/big"
)

type Backend interface {
	GetNextSerialNumber() (serialNumber *big.Int, err error)
	SetCAKeyPair(cakey interface{}, cacert *x509.Certificate) (err error)
	GetCAKeyPair() (cakey interface{}, cacert *x509.Certificate, err error)
	AddCertificate(cert *x509.Certificate) (err error)
	DeleteCertificate(serialNumber *big.Int) (err error)
	Certificate(serialNumber *big.Int) (cert *x509.Certificate, revoked bool, err error)
	Certificates(fn func(cert *x509.Certificate, revoked bool) (err error)) (err error)
	RevokeCertificate(serialNumber *big.Int) (err error)
	RecoverCertificate(serialNumber *big.Int) (err error)
}
