package ble

import (
	"crypto/ecdsa"
	"encoding/hex"
	"github.com/jarijaas/openssl"
	"github.com/muka/go-bluetooth/api/service"
	"github.com/muka/go-bluetooth/bluez/profile/agent"
	"github.com/muka/go-bluetooth/bluez/profile/gatt"
	"github.com/muka/go-bluetooth/hw"
	btmgmt2 "github.com/ouspg/tpm-bluetooth/pkg/btmgmt"
	"github.com/ouspg/tpm-bluetooth/pkg/crypto"
	log "github.com/sirupsen/logrus"
	"time"
)


var SENDER_CERT = `-----BEGIN CERTIFICATE-----
MIIDwzCCAaugAwIBAgIBDjANBgkqhkiG9w0BAQsFADCBpzELMAkGA1UEBhMCRkkx
ETAPBgNVBAgMCE1hcnlsYW5kMRIwEAYDVQQHDAlCYWx0aW1vcmUxGTAXBgNVBAoM
EFRlc3QgQ0EsIExpbWl0ZWQxIzAhBgNVBAsMGlNlcnZlciBSZXNlYXJjaCBEZXBh
cnRtZW50MRAwDgYDVQQDDAdUZXN0IENBMR8wHQYJKoZIhvcNAQkBFhB0ZXN0QGV4
YW1wbGUuY29tMCAXDTIwMDcxMjA5MjUwM1oYDzIyOTQwNDI2MDkyNTAzWjAPMQ0w
CwYDVQQDDAR0ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1vePGv1mZOIj
0gpqfCg1Ltbgkx8jlaKFiOfauoZ1SaFd7CtURrDzb/auZPtt9Me0pHVDvwmS51gb
VV86CM+dXaNaMFgwHQYDVR0OBBYEFPeyfqEqdYAhyC5jy+RYZyygciduMB8GA1Ud
IwQYMBaAFMXj03ZmATRFb30eDN75FBhufWKIMAkGA1UdEwQCMAAwCwYDVR0PBAQD
AgWgMA0GCSqGSIb3DQEBCwUAA4ICAQBfKCU/cbYVEdSCYffuu7CwlA7WD5nCtEBw
pL9bG6guLMZyBTWsKWmbx8RrA55iGyX1ws3bAxifzKHzYRSE1UA/oxxMCYEv389m
c+I41xLgQA7ys3/kEx9vJBSUXz5A68ksDJUUw+q0mPSI8vmLCej3hyBLloUUcEIq
ZKAtrkIKkxYtW/PaLXoDN7GVRX729II+poUChErAR/muexcgGYzmeoYsMkJqVUsx
MzQCUBqkzQL7IoLtWsd+2SLg7C6nmRsLAhFZulaikVw4guRJQ10XmU56gBkbhMmq
OYxvXjRDuqbvQYj20QIzNQAzPAkNAMb2yN1jO8snvkJlhWDkcYAtDbUFv4WeUuvI
ozvGN3TNNmbKWviFcw7hJD1VUtDNwM/Cowqpql+djOaxLNSmDjths4NGpjS+jrXX
8jtN64JBvtKg0s1vKjEKobdO4aGr6X3PGA8UGHJUO51mE9zuu4t5rdW5upuRCKCt
UsHlRrlxBkMD3BphaUwe0zwpHTWBuiYWaAoR+aX3724F67Btvj8A3QSNF+Dtdueg
K9cAkzaSbW6MqnoDIybsjnVxWv8eAH2hU9JyEFzquJIu2ooSK1czJ32wM1jPkl28
WaxsgoSV5sPm0QKFzIwCi7At160DDcoXweR4VXUCVlv2IsHRf2OmgpZjAtgzmRg0
9yDCfMDXlQ==
-----END CERTIFICATE-----`

const CHAR_CHUNK_SIZE = 500

var ephPrivKey *ecdsa.PrivateKey
var cipherSession *crypto.CipherSession

/**
Max char dat len is 512 bytes, simplest solution is to use multiple characteristic to deliver the data
Alternatively, sign only the pub key and deliver that only instead of the whole certificate
 */

/**
Supports only one simultaneous connection, good enough for poc
 */

const MY_SECURE_BLE_HWADDR = "DC:A6:32:28:34:E4"

func CreateKeyExchangeService(adapterID string, certificate []byte, privKeyPem []byte) error {

	privKey, err := openssl.LoadPrivateKeyFromPEM(privKeyPem)
	if err != nil {
		log.Fatalf("Could not load private key: %s", err)
	}

	/*ses, err := btmgmt2.CreateSession()
	if err != nil {
		log.Fatal(err)
	}
	defer ses.Close()
	ses.SetController(0)*/

	btmgmtCli := hw.NewBtMgmt(adapterID)
	btmgmtCli.SetPowered(false)

	btmgmtCli.SetLe(true)
	btmgmtCli.SetBredr(false)
	btmgmtCli.SetBondable(false)
	btmgmtCli.SetPairable(true)
	btmgmtCli.SetLinkLevelSecurity(false)
	btmgmtCli.SetConnectable(true)
	btmgmtCli.SetSsp(false)

	/*err = ses.SetSecureConnections(btmgmt2.SC_OFF)
	if err != nil {
		log.Fatal(err)
	}*/

	btmgmtCli.SetPowered(true)

	myH192, myR192, myH256, myR256, err := btmgmt2.ReadLocalOOBData(0)
	if err != nil {
		log.Fatalf("Could not read local oob data: %s", err)
	}

	log.Printf("Local OOB data (h192, r192, h256, r256): (%s, %s, %s, %s)",
		hex.EncodeToString(myH192[:]), hex.EncodeToString(myR192[:]),
		hex.EncodeToString(myH256[:]), hex.EncodeToString(myR256[:]))

	options := service.AppOptions{
		AdapterID:  adapterID,
		AgentCaps:  agent.CapNoInputNoOutput,
		UUIDSuffix: UUID_SUFFIX,
		UUID: APP_UUID,
	}

	a, err := service.NewApp(options)
	if err != nil {
		return err
	}
	defer a.Close()

	a.SetName("OOB exchange")

	if !a.Adapter().Properties.Powered {
		err = a.Adapter().SetPowered(true)
		if err != nil {
			log.Fatalf("Failed to power the adapter: %s", err)
		}
	}

	service1, err := a.NewService(SERVICE_UUID)
	if err != nil {
		return err
	}

	err = a.AddService(service1)
	if err != nil {
		return err
	}

	certChar, err := service1.NewChar(READ_CERT_1_CHAR_UUID)
	if err != nil {
		return err
	}

	certChar.Properties.Flags = []string{
		gatt.FlagCharacteristicRead,
	}

	certChar.OnRead(func(c *service.Char, options map[string]interface{}) ([]byte, error) {
		return certificate[0:CHAR_CHUNK_SIZE], nil
	})

	err = service1.AddChar(certChar)
	if err != nil {
		return err
	}

	certChar2, err := service1.NewChar(READ_CERT_2_CHAR_UUID)
	if err != nil {
		return err
	}

	certChar2.Properties.Flags = []string{
		gatt.FlagCharacteristicRead,
	}

	certChar2.OnRead(func(c *service.Char, options map[string]interface{}) ([]byte, error) {
		return certificate[CHAR_CHUNK_SIZE:2 * CHAR_CHUNK_SIZE], nil
	})

	err = service1.AddChar(certChar2)
	if err != nil {
		return err
	}

	certChar3, err := service1.NewChar(READ_CERT_3_CHAR_UUID)
	if err != nil {
		return err
	}

	certChar3.Properties.Flags = []string{
		gatt.FlagCharacteristicRead,
	}

	certChar3.OnRead(func(c *service.Char, options map[string]interface{}) ([]byte, error) {
		return certificate[2 * CHAR_CHUNK_SIZE:], nil
	})

	err = service1.AddChar(certChar3)
	if err != nil {
		return err
	}

	ecdhExchangeChar, err := service1.NewChar(ECDH_EXC_CHAR_UUID)
	if err != nil {
		return err
	}

	ecdhExchangeChar.Properties.Flags = []string{
		gatt.FlagCharacteristicWrite, gatt.FlagCharacteristicRead,
	}

	// Todo: prevent replay attacks, or protect ECDH priv key at least using TPM
	// Currently, if an adversary recovers the ECDH priv key and the signature, they could bypass the TPM
	// Although, if adversary has access to the ECDH priv key, they likely have TPM access anyway

	/**
	This is not really the best way to send response to write request, but documentation sucks and it is unclear how
	write request response should be read
	 */

	var exchangeRes []byte
	ecdhExchangeChar.OnRead(func(c *service.Char, options map[string]interface{}) (bytes []byte, err error) {
		return exchangeRes, nil
	})

	ecdhExchangeChar.OnWrite(func(c *service.Char, value []byte) ([]byte, error) {
		log.Info("GOT ECDH WRITE REQUEST")
		log.Print(options)

		exchangeData, err := UnmarshalECDHExchange(value)
		if err != nil {
			log.Fatalf("Could not unmarshal received ECDH exchange data: %s", err)
		}

		log.Printf("Received ECDH public key (key, sig): (%s, %s)\n",
			hex.EncodeToString(exchangeData.PubKey), hex.EncodeToString(exchangeData.Signature))

		originatorCert, err := openssl.LoadCertificateFromPEM([]byte(SENDER_CERT))
		if err != nil {
			log.Fatalf("Could not load pub key from PEM: %s", err)
		}
		pubKey, err := originatorCert.PublicKey()
		if err != nil {
			log.Fatalf("Could not get pub key from cert: %s", err)
		}

		err = crypto.Verify(pubKey, exchangeData.PubKey, exchangeData.Signature)
		if err != nil {
			log.Fatalf("Verification of received data failed: %s", err)
		}

		ephPrivKey, err = crypto.GenECDHPrivKey()
		if err != nil {
			log.Fatalf("Could not gen ECDH priv key: %s", err)
		}

		myPubKeyBytes := crypto.ECCPubKeyToBytes(&ephPrivKey.PublicKey)
		sig, err := crypto.Sign(privKey, myPubKeyBytes)
		if err != nil {
			log.Fatalf("Could not sign public key: %s", err)
		}

		responseData, err := MarshalECDHExchange(ECDHExchange{
			Signature: sig,
			PubKey: myPubKeyBytes,
		})
		if err != nil {
			log.Fatalf("Could not marshal ECDH exchange data: %s", err)
		}

		log.Printf("ECDH exchange response data: %s\n", string(responseData))

		originatorPubKey := crypto.BytesToECCPubKey(exchangeData.PubKey)
		log.Printf("Originator pubKeyX: %s", originatorPubKey.X.String())
		log.Printf("Originator pubKeyY: %s", originatorPubKey.Y.String())

		sessionKey := crypto.ComputeSessionKey(originatorPubKey, ephPrivKey)
		log.Printf("Session key: %s", hex.EncodeToString(sessionKey))

		cipherSession, err = crypto.NewCipherSession(sessionKey)
		if err != nil {
			log.Fatalf("Could not create session cipher: %s", err)
		}

		exchangeRes = responseData
		return responseData, nil
	})

	err = service1.AddChar(ecdhExchangeChar)
	if err != nil {
		return err
	}

	oobExchangeChar, err := service1.NewChar(OOB_EXC_CHAR_UUID)
	if err != nil {
		return err
	}

	oobExchangeChar.Properties.Flags = []string{
		gatt.FlagCharacteristicWrite, gatt.FlagCharacteristicRead,
	}


	var oobDataRes []byte
	oobExchangeChar.OnRead(func(c *service.Char, options map[string]interface{}) (bytes []byte, err error) {
		return oobDataRes, nil
	})

	oobExchangeChar.OnWrite(func(c *service.Char, value []byte) (bytes []byte, err error) {

		ciphertext, err := crypto.UnmarshalNoncedCiphertext(value)
		if err != nil {
			log.Fatalf("Could not unmarshal ciphertext: %s", ciphertext)
		}

		plaintext, err := cipherSession.Decrypt(ciphertext)
		if err != nil {
			log.Fatalf("Could not decrypt ciphertext: %s", err)
		}

		log.Printf("OOB data received: %s\n", plaintext)

		oobExchange, err := UnmarshalOOBExchange(plaintext)
		if err != nil {
			log.Fatalf("Could not unmarshal oob exchange data: %s", err)
		}

		h192 := oobExchange.Data[:16]
		r192 := oobExchange.Data[16:]

		err = btmgmt2.AddRemoteOOBData(0, oobExchange.Address, btmgmt2.LE_PUBLIC,
			nil , nil, h192[:], r192[:])
		if err != nil {
			log.Fatalf("Could not add remote oob data: %s", err)
		}
		log.Infof("Added remote oob data for address: %s\n", oobExchange.Address)

		var oobData [32]byte
		copy(oobData[:16], myH256[:])
		copy(oobData[16:], myR256[:])

		resData, err := MarshalOOBExchange(OOBExchange{
			Data:    oobData,
			Address: MY_SECURE_BLE_HWADDR,
		})
		if err != nil {
			log.Fatalf("Could not marshal oob data response: %s", err)
		}

		respCiphertext, err := cipherSession.Encrypt(resData)
		if err != nil {
			log.Fatalf("Could not encrypt response oob data: %s", err)
		}

		res, err := crypto.MarshalNoncedCiphertext(respCiphertext)
		if err != nil {
			log.Fatalf("Could not marshal response oob data ciphertext: %s", err)
		}
		oobDataRes = res

		go func() {
			ses, err := btmgmt2.CreateSession()
			if err != nil {
				log.Fatal(err)
			}
			defer ses.Close()
			ses.SetController(0)

			time.Sleep(10 * time.Second)

			err = ses.Pair(oobExchange.Address, btmgmt2.LE_PUBLIC, btmgmt2.NoInputNoOutput)
			if err != nil {
				log.Fatalf("Could not pair with the device. Reason: %s\n", err)
			}
		}()

		return
	})

	err = service1.AddChar(oobExchangeChar)
	if err != nil {
		return err
	}

	err = a.Run()
	if err != nil {
		return err
	}

	log.Infof("Exposed service %s", service1.Properties.UUID)

	timeout := uint32(6 * 3600) // 6h
	log.Infof("Advertising for %ds...", timeout)
	cancel, err := a.Advertise(timeout)
	if err != nil {
		return err
	}

	defer cancel()

	wait := make(chan bool)
	go func() {
		time.Sleep(time.Duration(timeout) * time.Second)
		wait <- true
	}()

	<-wait

	return nil
}
