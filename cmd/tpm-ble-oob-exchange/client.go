package main

import (
	"encoding/hex"
	"github.com/jarijaas/openssl"
	"github.com/ouspg/tpm-bluetooth/pkg/ble"
	"github.com/ouspg/tpm-bluetooth/pkg/btmgmt"
	"github.com/ouspg/tpm-bluetooth/pkg/crypto"
	log "github.com/sirupsen/logrus"
	"time"
)

const TARGET_HWADDR = "DC:A6:32:28:34:E4"

const MY_SECURE_BLE_HWADDR = "B8:27:EB:3A:89:0A"
const TARGET_SECURE_BLE_HWADDR = TARGET_HWADDR

func main()  {
	err := crypto.InitializeTPMEngine()
	if err != nil {
		log.Fatalf("Could not initialize TPM engine: %s", err)
	}

	bleDev, err := ble.CreateConnection("hci0", TARGET_HWADDR)
	if err != nil {
		log.Fatalf("Could not connect to BLE remote: %s", err)
	}

	pemCert, err := ble.ReadCertificate(bleDev)
	if err != nil {
		log.Fatalf("Could not read certificate. Error: %s", err)
	}

	log.Printf("Certificate: \n%s\n", string(pemCert))

	log.Println("Verify certificate")

	err = crypto.VerifyCertificate(ble.TRUSTED_CA, pemCert)
	if err != nil {
		log.Fatalf("Could not verify certificate. Error: %s", err)
	}

	serverCert, err := openssl.LoadCertificateFromPEM(pemCert)
	if err != nil {
		log.Fatalf("Could not read cert")
	}
	serverPub, err := serverCert.PublicKey()
	if err != nil {
		log.Fatalf("Could not read public key")
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

	log.Println("Verify signature")
	err = crypto.Verify(serverPub, exchangeResponse.PubKey, exchangeResponse.Signature)
	if err != nil {
		log.Fatalf("Server public key signature is not valid: %s", err)
	}

	serverPubKey := crypto.BytesToECCPubKey(exchangeResponse.PubKey)

	sessionKey := crypto.ComputeSessionKey(serverPubKey, ephKey)
	log.Printf("Session key: %s\n", hex.EncodeToString(sessionKey[:]))

	cipherSession, err := crypto.NewCipherSession(sessionKey)
	if err != nil {
		log.Fatalf("Could not create cipher session: %s", err)
	}

	oobData, err := ble.ExchangeOOBData(bleDev, cipherSession, MY_SECURE_BLE_HWADDR)
	if err != nil {
		log.Fatalf("Could not exchange tokens: %s", err)
	}

	log.Printf("Received oob data: %s", hex.EncodeToString(oobData.Data[:]))

	oobHash := oobData.Data[:16]
	oobRandomizer := oobData.Data[16:]

	err = btmgmt.AddRemoteOOBData(0, oobData.Address, btmgmt.LE_PUBLIC,
		nil, nil, oobHash, oobRandomizer)
	if err != nil {
		log.Fatalf("Could not add remote oob data for address: %s. Reason: %s\n", oobData.Address, err)
	}
	log.Infof("Added remote oob data for address: %s\n", oobData.Address)

	time.Sleep(15 * time.Second)

	ses, err := btmgmt.CreateSession()
	if err != nil {
		log.Fatal(err)
	}
	defer ses.Close()
	ses.SetController(0)

	err = ses.Pair(oobData.Address, btmgmt.LE_PUBLIC, btmgmt.NoInputNoOutput)
	if err != nil {
		log.Fatalf("Could not pair with the device. Reason: %s\n", err)
	}
}
