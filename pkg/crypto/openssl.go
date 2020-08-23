	package crypto

import (
	"encoding/pem"
	"fmt"
	"github.com/jarijaas/openssl"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
)

/*
Returns no error (nil) if certificate is valid
*/
func VerifyCertificate(certPath string, certPEM []byte) error {

	caCertPEM, err := ioutil.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("could not read CA certificate. Reason: %s", err)
	}

	log.Printf("CA CERT:\n%s\n", string(caCertPEM))

	caCert, err := openssl.LoadCertificateFromPEM(caCertPEM)
	if err != nil {
		return fmt.Errorf("could not load CA certificate. Reason: %s", err)
	}

	cert, err := openssl.LoadCertificateFromPEM(certPEM)
	if err != nil {
		return fmt.Errorf("could not load certificate. Reason: %s", err)
	}

	certStore, err := openssl.NewCertificateStore()
	if err != nil {
		return fmt.Errorf("could not create certificate store. Reason: %s", err)
	}

	err = certStore.AddCertificate(caCert)
	if err != nil {
		return fmt.Errorf("could not add cert to cert store. %s", err)
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

var tpmEngine *openssl.Engine

/**
Load tpm2tss engine and set is as default
Should be called before other functions
 */
func InitializeTPMEngine() error {
	var err error

	tpmEngine, err = openssl.EngineById("tpm2tss")
	if err != nil {
		return fmt.Errorf("could not load engine: %s", err)
	}

	err = openssl.SetEngineAsDefault(tpmEngine)
	if err != nil {
		return fmt.Errorf("could not set engine as default: %s", err)
	}

	return nil
}

/**
Load TPM wrapped priv key, priv key is protected by the TPM.
If the key is TSS2 (TPM wrapped priv key), but tpm engine is not initialized,
this function initializes the openssl TPM engine.
If the key is not TPM wrapped key, the key is loaded normally
 */
func LoadPrivateKey(privKeyPath string) (openssl.PrivateKey, error) {
	privKeyPem, err := ioutil.ReadFile(privKeyPath)

	decodedPem, _ := pem.Decode(privKeyPem)

	log.Info("Private key type: ", decodedPem.Type)

	isTSS2Key := decodedPem.Type == "TSS2 PRIVATE KEY"

	if !isTSS2Key {
		log.Warn("Private key is not TPM protected!")

		if err != nil {
			return nil, fmt.Errorf("could not load private key: %s", err)
		}

		privKey, err := openssl.LoadPrivateKeyFromPEM(privKeyPem)
		if err != nil {
			return nil, fmt.Errorf("could not load private key: %s", err)
		}

		return privKey, nil
	}

	if tpmEngine == nil {
		log.Info("Initialize TPM openssl engine")
		err = InitializeTPMEngine()
		if err != nil {
			return nil, err
		}
	}

	privKey, err := openssl.EngineLoadPrivateKey(tpmEngine, privKeyPath)
	if err != nil {
		return nil, fmt.Errorf("could not load private key: %s", err)
	}
	return privKey, nil
}

/**
Sign data using the priv key and SHA256 (PKCS1v15)
 */
func Sign(privKey openssl.PrivateKey, data []byte) ([]byte, error) {
	dataSig, err := privKey.SignPKCS1v15(openssl.SHA256_Method, data)
	if err != nil {
		return nil, fmt.Errorf("could not sign data: %s", err)
	}

	return dataSig, nil
}

func Verify(pubKey openssl.PublicKey, data []byte, sig []byte) error {
	return pubKey.VerifyPKCS1v15(openssl.SHA256_Method, data, sig)
}