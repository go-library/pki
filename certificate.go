package pki

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"
)

type CertManager struct {
	backend Backend
	cacert  *x509.Certificate
	cakey   interface{}
}

func OpenCertManager(backend Backend) (cm *CertManager, err error) {
	cm = new(CertManager)
	cm.backend = backend
	cm.cakey, cm.cacert, err = cm.backend.GetCAKeyPair()
	if err != nil {
		return nil, err
	}

	return cm, nil
}

func CreateCertManager(backend Backend, cakey interface{}, cacert *x509.Certificate, needSelfSign bool) (cm *CertManager, err error) {
	cm = new(CertManager)
	cm.backend = backend
	err = cm.setCAKeyPair(cakey, cacert, needSelfSign)
	if err != nil {
		return nil, err
	}

	cm.cakey, cm.cacert, err = cm.backend.GetCAKeyPair()
	if err != nil {
		return nil, err
	}

	return cm, nil
}

func (cm *CertManager) setCAKeyPair(cakey interface{}, cacert *x509.Certificate, needSelfSign bool) (err error) {
	var (
		certData []byte
		certs    []*x509.Certificate
	)

	if key, cert, err := cm.backend.GetCAKeyPair(); err == nil && key != nil && cert != nil {
		return fmt.Errorf("CA Certificate is already registered")
	}

	if needSelfSign {
		if nil == cacert.PublicKey {
			err = fmt.Errorf("request's PublicKey value is nil")
			if err != nil {
				return err
			}
		}

		cacert.SerialNumber, err = cm.backend.GetNextSerialNumber()
		if err != nil {
			return err
		}

		cacert.AuthorityKeyId = cacert.SubjectKeyId
		certData, err = x509.CreateCertificate(rand.Reader, cacert, cacert, cacert.PublicKey, cakey)
		if err != nil {
			return err
		}

		certs, err = x509.ParseCertificates(certData)
		if err != nil {
			return err
		}

		cacert = certs[0]
		err = cm.backend.AddCert(cacert)
		if err != nil {
			return err
		}
	}

	err = cm.backend.SetCAKeyPair(cakey, cacert)
	if err != nil {
		return err
	}

	return nil
}

func (cm *CertManager) Sign(template *x509.Certificate) (cert *x509.Certificate, err error) {
	var (
		asn1Data []byte
		certs    []*x509.Certificate
	)

	if nil == template.PublicKey {
		return nil, fmt.Errorf("request's PublicKey value is nil")
	}

	template.SerialNumber, err = cm.backend.GetNextSerialNumber()
	if err != nil {
		return nil, err
	}

	template.AuthorityKeyId = cm.cacert.SubjectKeyId
	asn1Data, err = x509.CreateCertificate(rand.Reader, template, cm.cacert, template.PublicKey, cm.cakey)
	if err != nil {
		return nil, err
	}

	certs, err = x509.ParseCertificates(asn1Data)
	if err != nil {
		return nil, err
	}

	cert = certs[0]
	err = cm.backend.AddCert(cert)
	if err != nil {
		return nil, err
	}

	return cert, nil
}
