package pki

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

const (
	RSA_1024      = "RSA_1024"
	RSA_2048      = "RSA_2048"
	ECDSA_P256    = "ECDSA_P256"
	ECDSA_P384    = "ECDSA_P384"
	ECDSA_P521    = "ECDSA_P521"
	DSA_L1024N160 = "DSA_L1024N160"
	DSA_L2048N224 = "DSA_L2048N224"
	DSA_L2048N256 = "DSA_L2048N256"
)

type algorithm string

func CreatePrivateKey(algo algorithm) (privatekey interface{}, err error) {
	switch algo {
	case RSA_1024:
		return rsa.GenerateKey(rand.Reader, 1024)
	case RSA_2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case DSA_L1024N160:
		params := new(dsa.Parameters)
		dsakey := new(dsa.PrivateKey)
		err = dsa.GenerateParameters(params, rand.Reader, dsa.L1024N160)
		if err != nil {
			return nil, err
		}
		dsakey.PublicKey.Parameters = *params
		err = dsa.GenerateKey(dsakey, rand.Reader)
		if err != nil {
			return nil, err
		}
		return dsakey, nil
	case DSA_L2048N224:
		params := new(dsa.Parameters)
		dsakey := new(dsa.PrivateKey)
		err = dsa.GenerateParameters(params, rand.Reader, dsa.L2048N224)
		if err != nil {
			return nil, err
		}

		dsakey.PublicKey.Parameters = *params
		err = dsa.GenerateKey(dsakey, rand.Reader)
		if err != nil {
			return nil, err
		}
		return dsakey, nil
	case DSA_L2048N256:
		params := new(dsa.Parameters)
		dsakey := new(dsa.PrivateKey)
		err = dsa.GenerateParameters(params, rand.Reader, dsa.L2048N256)
		if err != nil {
			return nil, err
		}
		dsakey.PublicKey.Parameters = *params
		err = dsa.GenerateKey(dsakey, rand.Reader)
		if err != nil {
			return nil, err
		}
		return dsakey, nil
	case ECDSA_P256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case ECDSA_P384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case ECDSA_P521:
		return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		return nil, fmt.Errorf("unrecognized algorithm: %q", algo)
	}

	return privatekey, nil
}

func ToPublicKey(priv interface{}) interface{} {
	switch pk := priv.(type) {
	case *rsa.PrivateKey:
		return &pk.PublicKey
	case *dsa.PrivateKey:
		return &pk.PublicKey
	case *ecdsa.PrivateKey:
		return &pk.PublicKey
	default:
		return nil
	}
}
