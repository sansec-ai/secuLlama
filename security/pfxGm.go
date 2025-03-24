package security

import (
	"encoding/base64"
	"errors"
	"log"

	g12 "github.com/sansec-ai/gmsm/pkcs12"
	"github.com/sansec-ai/gmsm/sm2"
	gx "github.com/sansec-ai/gmsm/x509"
)

func ParsePrivateKey(keyData []byte) (*sm2.PrivateKey, error) {
	p8key, err := gx.ParsePKCS8UnecryptedPrivateKey(keyData)
	if err == nil {
		return p8key, nil
	}

	return nil, errors.New("failed to parse private key")
}
func ParseCertgx509(certData []byte) (*gx.Certificate, error) {
	cert, err := gx.ParseCertificate(certData)
	if err == nil {
		return cert, nil
	}

	return nil, errors.New("failed to parse certificate")
}
func ParsePkcs12Cert(password string, pfgxData []byte) (*gx.Certificate, *sm2.PrivateKey, error) {
	safeBags, err := g12.ToPEM(pfgxData, password)
	if err != nil || len(safeBags) == 0 {
		pfgxData, err = base64.StdEncoding.DecodeString(string(pfgxData))
		if err != nil {
			log.Println("Base64 decode pfgx error:", err.Error())
			return nil, nil, err
		}
		safeBags, err = g12.ToPEM(pfgxData, password)
		if err != nil {
			log.Println(err.Error())
			return nil, nil, err
		}
	}

	var privateKey []byte
	for _, safeBag := range safeBags {
		if safeBag.Type == "PRIVATE KEY" {
			privateKey = safeBag.Bytes
			break
		}
	}
	if privateKey == nil {
		return nil, nil, errors.New("private key not found")
	}

	var sm2Priv *sm2.PrivateKey
	var sm2Cert *gx.Certificate
	sm2Priv, err = ParsePrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	var cert []byte
	for _, safeBag := range safeBags {
		if safeBag.Type != "CERTIFICATE" {
			continue
		}

		sm2Cert, err = ParseCertgx509(safeBag.Bytes)
		if err != nil {
			continue
		}

		cert = safeBag.Bytes
		break
	}

	if cert == nil {
		return nil, nil, errors.New("certificate not found or does not match private key")
	}
	return sm2Cert, sm2Priv, nil
}
