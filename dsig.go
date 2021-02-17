package dsig

import (
	"crypto"
	"encoding/base64"

	"github.com/noshto/dsig/pkg/safenet"
	"github.com/noshto/dsig/pkg/signedxml"
	"github.com/noshto/sep"

	"github.com/beevik/etree"
)

// Params represents set of parameters needed for calling Sign function
type Params struct {
	SepConfig     *sep.Config
	SafenetConfig *safenet.Config
	InFile        string
	OutFile       string
}

// Sign signs given xml
func Sign(params *Params) error {

	doc := etree.NewDocument()
	if err := doc.ReadFromFile(params.InFile); err != nil {
		return err
	}

	// Initialize Signer
	signer := &safenet.SafeNet{}
	if err := signer.Initialize(params.SafenetConfig); err != nil {
		return err
	}
	defer signer.Finalize()

	// Fill in certificate and subject of signature element
	cert, err := signer.GetCertificate()
	if err != nil {
		return err
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
		return err
	}
	cSigner := crypto.Signer(signer)
	xmlSigner, err := signedxml.NewSigner(str, &cSigner)
	if err != nil {
		return err
	}
	xmlSigner.SetReferenceIDAttribute("Id")
	str, err = xmlSigner.Sign()
	if err != nil {
		return err
	}
	doc = etree.NewDocument()
	if err = doc.ReadFromString(str); err != nil {
		return err
	}

	doc.IndentTabs()
	doc.Root().SetTail("")

	return doc.WriteToFile(params.OutFile)
}
