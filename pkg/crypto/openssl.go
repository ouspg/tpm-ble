package crypto

import (
	"errors"
	"fmt"
	"github.com/jarijaas/openssl"
)

/*
Returns no error (nil) if certificate is valid
*/
func VerifyCertificate(caCertPEM []byte, certPEM []byte) error {
	caCert, err := openssl.LoadCertificateFromPEM(caCertPEM)
	if err != nil {
		return errors.New("could not load CA certificate")
	}

	cert, err := openssl.LoadCertificateFromPEM(certPEM)
	if err != nil {
		return errors.New("could not load certificate")
	}

	certStore, err := openssl.NewCertificateStore()
	if err != nil {
		return errors.New("could not create certificate store")
	}

	err = certStore.AddCertificate(caCert)
	if err != nil {
		return fmt.Errorf("could not add cert to cert store: %s", err)
	}

	_, verifyRes, err := cert.VerifyTrustAndGetIssuerCertificate(certStore)
	if err != nil {
		return fmt.Errorf("error during cert verification: %s", err)
	}
	if verifyRes != openssl.Ok {
		return fmt.Errorf("certificate verification failed. VerifyResult: %d", verifyRes)
	}

	return nil
}