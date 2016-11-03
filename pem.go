package pki

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
)

func EncodePEM(key interface{}) (asn1Data []byte, err error) {
	var (
		block *pem.Block
	)

	switch key := key.(type) {
	case *rsa.PrivateKey:
		asn1Data = x509.MarshalPKCS1PrivateKey(key)
		block = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: asn1Data}
	case *dsa.PrivateKey:
		asn1Data, err = asn1.Marshal(*key)
		if err != nil {
			return nil, err
		}
		block = &pem.Block{Type: "DSA PRIVATE KEY", Bytes: asn1Data}
	case *ecdsa.PrivateKey:
		asn1Data, err = x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, err
		}
		block = &pem.Block{Type: "EC PRIVATE KEY", Bytes: asn1Data}
	case *x509.Certificate:
		block = &pem.Block{Type: "CERTIFICATE", Bytes: key.Raw}
	default:
		return nil, fmt.Errorf("unkown private key type")
	}

	return pem.EncodeToMemory(block), nil
}

func DecodePEM(data []byte) (key interface{}, err error) {
	var (
		block *pem.Block
	)

	block, _ = pem.Decode(data)
	if block == nil {
		err = fmt.Errorf("failed to decode pem.")
	}

	if err != nil {
		return
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "DSA PRIVATE KEY":
		dsaPriv := new(dsa.PrivateKey)
		_, err = asn1.Unmarshal(block.Bytes, dsaPriv)
		key = dsaPriv
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "CERTIFICATE":
		var certs []*x509.Certificate
		certs, err = x509.ParseCertificates(block.Bytes)
		if len(certs) == 0 {
			return nil, fmt.Errorf("there is no certificates")
		} else {
			key = certs[0]
		}
	default:
		return nil, fmt.Errorf("unkown block type: %s", block.Type)
	}

	return key, err
}
