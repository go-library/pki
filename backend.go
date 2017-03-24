package pki

import (
	"crypto/x509"
	"math/big"
)

type Backend interface {
	GetNextSerialNumber() (serialNumber *big.Int, err error)

	SetCAKeyPair(cakey interface{}, cacert *x509.Certificate) (err error)
	GetCAKeyPair() (cakey interface{}, cacert *x509.Certificate, err error)

	AddCert(cert *x509.Certificate) (err error)

	DelCert(serialNumber *big.Int) (err error)
	GetCert(serialNumber *big.Int) (cert *x509.Certificate, err error)

	RevoketCert(serialNumber *big.Int) (err error)
	RecoverCert(serialNumber *big.Int) (err error)

	GetSerialNumbers() (serialNumbers chan *big.Int, err error)
}
