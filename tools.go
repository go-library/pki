package pki

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
)

func CreateHashSubjectKeyId(pub interface{}) (hash []byte, err error) {
	var (
		input []byte
	)

	switch k := pub.(type) {
	case *rsa.PublicKey:
		bs := make([]byte, 4)
		binary.PutVarint(bs, int64(k.E))
		input = append(k.N.Bytes(), bs...)
	case *dsa.PublicKey:
		input = k.Y.Bytes()
	case *ecdsa.PublicKey:
		input = append(k.X.Bytes(), k.Y.Bytes()...)
	default:
		return nil, fmt.Errorf("unkown certificate public key type: %v", k)
	}

	sum := sha1.Sum(input)
	return sum[:], nil
}
