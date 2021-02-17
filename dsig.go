package dsig

import (
	"crypto"
	"crypto/x509"
	"dsig/pkg/signedxml"
	"encoding/base64"

	"github.com/beevik/etree"
)

// CertificateProvider defines an interface that provides x509 certificate
type CertificateProvider interface {
	X509() (x509.Certificate, error)
}

// PKCS1v15Signer defines an extension for crypto.Signer which also supports pkcs1v15 signature
type PKCS1v15Signer interface {
	crypto.Signer
	SignPKCS1v15(data []byte) ([]byte, error)
}

// Signer represents an interface of signer
type Signer struct {
	Signer      PKCS1v15Signer
	Certificate CertificateProvider
}

// Sign signs given xml. Prerequisites: xml document should be completely formed, eg signature-related elements should exists
func (s *Signer) Sign(doc *etree.Document) (*etree.Document, error) {

	// Fill in certificate and subject of signature element
	cert, err := s.Certificate.X509()
	if err != nil {
		return nil, err
	}

	x509Cert := doc.FindElement("//X509Certificate")
	if nil != x509Cert {
		x509Cert.SetText(base64.StdEncoding.EncodeToString(cert.Raw))
	}
	sub := doc.FindElement("//X509SubjectName")
	if nil != sub {
		sub.SetText(cert.Subject.String())
	}

	// sign
	str, err := doc.WriteToString()
	if err != nil {
		return nil, err
	}
	var cSigner crypto.Signer = s.Signer.(crypto.Signer)
	signer, err := signedxml.NewSigner(str, &cSigner)
	if err != nil {
		return nil, err
	}
	signer.SetReferenceIDAttribute("Id")
	str, err = signer.Sign()
	if err != nil {
		return nil, err
	}
	doc = etree.NewDocument()
	err = doc.ReadFromString(str)
	if err != nil {
		return nil, err
	}
	return doc, nil
}
