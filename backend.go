package pki

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"github.com/boltdb/bolt"
	"math/big"
	"time"
)

type Backend interface {
	GetNextSerialNumber() (serialNumber *big.Int, err error)
	SetCAKeyPair(cakey interface{}, cacert *x509.Certificate) (err error)
	GetCAKeyPair() (cakey interface{}, cacert *x509.Certificate, err error)
	AddCert(cert *x509.Certificate) (err error)
	VisitAll(fn func(cert *x509.Certificate) error) (err error)

	GetCert(serialNumber *big.Int) (cert *x509.Certificate, err error)

	SetIndex(key []byte, cert *x509.Certificate) (err error)
	GetIndex(key []byte) (cert *x509.Certificate, err error)
}

type BoltBackend struct {
	db *bolt.DB
}

func NewBoltBackend(dbfile string) (b *BoltBackend, err error) {
	b = new(BoltBackend)
	b.db, err = bolt.Open(dbfile, 0600, &bolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (b *BoltBackend) GetNextSerialNumber() (serialNumber *big.Int, err error) {
	var (
		serialBytes []byte
		metaBucket  *bolt.Bucket
	)

	err = b.db.Update(func(tx *bolt.Tx) error {
		metaBucket, err = tx.CreateBucketIfNotExists([]byte("MetaBucket"))
		if err != nil {
			return err
		}

		serialBytes = metaBucket.Get([]byte("nextSerialNumber"))
		if nil == serialBytes {
			serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
			serialNumber, err = rand.Int(rand.Reader, serialNumberLimit)
			if err != nil {
				return err
			}
		} else {
			serialNumber = new(big.Int)
			serialNumber.SetBytes(serialBytes)
			serialNumber = serialNumber.Add(serialNumber, big.NewInt(1))
		}

		err = metaBucket.Put([]byte("nextSerialNumber"), serialNumber.Bytes())
		if err != nil {
			return err
		}

		return nil
	})

	return serialNumber, err
}

func (b *BoltBackend) SetCAKeyPair(cakey interface{}, cacert *x509.Certificate) (err error) {
	err = b.db.Update(func(tx *bolt.Tx) (err error) {
		var (
			metaBucket *bolt.Bucket
			cacertPEM  []byte
			cakeyPEM   []byte
		)

		metaBucket, err = tx.CreateBucketIfNotExists([]byte("MetaBucket"))
		if err != nil {
			return err
		}

		cakeyPEM, err = EncodePEM(cakey)
		if err != nil {
			return err
		}

		metaBucket.Put([]byte("cakey"), cakeyPEM)

		cacertPEM, err = EncodePEM(cacert)
		if err != nil {
			return err
		}

		metaBucket.Put([]byte("cacert"), cacertPEM)

		return err
	})

	if err != nil {
		return err
	}

	return err
}

func (b *BoltBackend) GetCAKeyPair() (cakey interface{}, cacert *x509.Certificate, err error) {
	var (
		c    interface{}
		data []byte
	)

	err = b.db.View(func(tx *bolt.Tx) (err error) {
		var (
			metaBucket = tx.Bucket([]byte("MetaBucket"))
		)

		if metaBucket == nil {
			return fmt.Errorf("there is no MetaBucket")
		}

		data = metaBucket.Get([]byte("cakey"))
		cakey, err = DecodePEM(data)
		if err != nil {
			return err
		}

		data = metaBucket.Get([]byte("cacert"))
		c, err = DecodePEM(data)
		if err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return nil, nil, err
	}

	if cert, ok := c.(*x509.Certificate); !ok {
		return nil, nil, fmt.Errorf("cacert is not a certificate")
	} else {
		cacert = cert
	}

	return cakey, cacert, nil

}

func (b *BoltBackend) AddCert(cert *x509.Certificate) (err error) {
	var (
		certBucket *bolt.Bucket
	)

	err = b.db.Update(func(tx *bolt.Tx) error {
		var (
			data []byte
		)
		certBucket, err = tx.CreateBucketIfNotExists([]byte("CertBucket"))
		if err != nil {
			return err
		}

		data, err = EncodePEM(cert)
		if err != nil {
			return err
		}

		err = certBucket.Put(cert.SerialNumber.Bytes(), data)
		if err != nil {
			return err
		}

		return nil
	})

	return err

}

func (b *BoltBackend) VisitAll(fn func(cert *x509.Certificate) error) (err error) {
	err = b.db.View(func(tx *bolt.Tx) error {
		var (
			certBucket = tx.Bucket([]byte("CertBucket"))
			key        interface{}
		)

		err = certBucket.ForEach(func(k, v []byte) error {
			key, err = DecodePEM(v)
			if err != nil {
				return err
			}
			if cert, ok := key.(*x509.Certificate); ok {
				err = fn(cert)
			} else {
				err = fmt.Errorf("type assertion failure")
			}
			return err
		})

		return err
	})

	if err != nil {
		return err
	}

	return nil
}

func (b *BoltBackend) GetCert(serialNumber *big.Int) (cert *x509.Certificate, err error) {
	err = b.db.View(func(tx *bolt.Tx) error {
		var (
			certBucket = tx.Bucket([]byte("CertBucket"))
			key        interface{}
		)

		key, err = DecodePEM(certBucket.Get(serialNumber.Bytes()))
		if err != nil {
			return err
		}
		cert = key.(*x509.Certificate)
		return nil
	})

	if err != nil {
		return nil, err
	}

	return cert, nil
}

func (b *BoltBackend) SetIndex(key []byte, cert *x509.Certificate) (err error) {
	return nil
}

func (b *BoltBackend) GetIndex(key []byte) (cert *x509.Certificate, err error) {
	return nil, nil

}
