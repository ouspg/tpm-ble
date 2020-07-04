package main

import (
	"encoding/hex"
	"github.com/ouspg/tpm-bluetooth/pkg/ble"
	"github.com/ouspg/tpm-bluetooth/pkg/crypto"
	"log"
)

func main()  {
	err := crypto.InitializeTPMEngine()
	if err != nil {
		log.Fatalf("Could not initialize TPM engine: %s", err)
	}

	bleDev, err := ble.CreateConnection("hci0", "00:1A:7D:DA:71:07")
	if err != nil {
		log.Fatalf("Could not connect to BLE remote: %s", err)
	}

	pemCert, err := ble.ReadCertificate(bleDev)
	if err != nil {
		log.Fatalf("Could not read certificate. Error: %s", err)
	}

	log.Printf("Certificate: \n%s\n", string(pemCert))

	log.Println("Verify certificate")

	err = crypto.VerifyCertificate([]byte(ble.TRUSTED_CA), pemCert)
	if err != nil {
		log.Fatalf("Could not verify certificate. Error: %s", err)
	}

	log.Println("Certificate was deemed valid (signed by the CA)")

	signingPrivKey, err := crypto.LoadTPMPrivateKey("/usr/local/share/keys/tpm_priv.key")
	if err != nil {
		log.Fatalf("Could not load TPM private key used in signing: %s", err)
	}

	ephKey, err := crypto.GenECDHPrivKey()
	if err != nil {
		log.Fatalf("Could not generate ephemeral key for ECDH: %s", err)
	}

	pubKeyBytes := crypto.ECCPubKeyToBytes(&ephKey.PublicKey)
	log.Printf("Sign: %s\n", hex.EncodeToString(pubKeyBytes))

	pubKeySig, err := crypto.Sign(signingPrivKey, pubKeyBytes)
	if err != nil {
		log.Fatalf("Could not sign ECDH pub key: %s", err)
	}

	log.Printf("ECDH pub key signature: %s", hex.EncodeToString(pubKeySig))

	log.Printf("Send ECDH pub key, certificate and the signature to the other party")

	exchangeResponse, err := ble.BeginECDHExchange(bleDev, ble.ECDHExchange{
		Signature: pubKeySig,
		PubKey:    pubKeyBytes,
	})
	if err != nil {
		log.Fatalf("ECDH exhange failed: %s", err)
	}

	log.Printf("Received pub key (key, sig): (%s, %s)",
		hex.EncodeToString(exchangeResponse.PubKey), hex.EncodeToString(exchangeResponse.Signature))

	serverPubKey := crypto.BytesToECCPubKey(exchangeResponse.PubKey)

	sessionKey := crypto.ComputeSessionKey(serverPubKey, ephKey)
	log.Printf("Session key: %s\n", hex.EncodeToString(sessionKey[:]))

	cipherSession, err := crypto.NewCipherSession(sessionKey)
	if err != nil {
		log.Fatalf("Could not create cipher session: %s", err)
	}

	data, err := ble.ExchangeTokens(bleDev, cipherSession)
	if err != nil {
		log.Fatalf("Could not exhange tokens: %s", err)
	}

	log.Printf("Received token: %s", data)


}
