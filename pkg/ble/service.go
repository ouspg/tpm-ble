package ble

import (
	"crypto/ecdsa"
	"encoding/hex"
	"github.com/jarijaas/openssl"
	"github.com/muka/go-bluetooth/api/service"
	"github.com/muka/go-bluetooth/bluez/profile/agent"
	"github.com/muka/go-bluetooth/bluez/profile/gatt"
	"github.com/muka/go-bluetooth/hw"
	"github.com/ouspg/tpm-bluetooth/pkg/crypto"
	log "github.com/sirupsen/logrus"
	"os"
	"time"
)

func serve(adapterID string) error {

	options := service.AppOptions{
		AdapterID:  adapterID,
		AgentCaps:  agent.CapNoInputNoOutput,
		UUIDSuffix: "-0000-1000-8000-00805F9B34FB",
		UUID:       "1234",
	}

	a, err := service.NewApp(options)
	if err != nil {
		return err
	}
	defer a.Close()

	a.SetName("go_bluetooth")

	log.Infof("HW address %s", a.Adapter().Properties.Address)

	if !a.Adapter().Properties.Powered {
		err = a.Adapter().SetPowered(true)
		if err != nil {
			log.Fatalf("Failed to power the adapter: %s", err)
		}
	}

	service1, err := a.NewService("2233", )
	if err != nil {
		return err
	}


	err = a.AddService(service1)
	if err != nil {
		return err
	}

	char1, err := service1.NewChar("3344")
	if err != nil {
		return err
	}

	char1.Properties.Flags = []string{
		gatt.FlagCharacteristicRead,
		gatt.FlagCharacteristicWrite,
	}

	char1.OnRead(func(c *service.Char, options map[string]interface{}) ([]byte, error) {
		log.Warnf("GOT READ REQUEST")
		return []byte{42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42}, nil
	})

	char1.OnWrite(func(c *service.Char, value []byte) ([]byte, error) {
		log.Warnf("GOT WRITE REQUEST")
		return value, nil
	})

	err = service1.AddChar(char1)
	if err != nil {
		return err
	}

	descr1, err := char1.NewDescr("4455")
	if err != nil {
		return err
	}

	descr1.Properties.Flags = []string{
		gatt.FlagDescriptorEncryptAuthenticatedRead,
		gatt.FlagDescriptorEncryptAuthenticatedWrite,
	}

	descr1.OnRead(func(c *service.Descr, options map[string]interface{}) ([]byte, error) {
		log.Warnf("GOT READ REQUEST")
		return []byte{42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42}, nil
	})
	descr1.OnWrite(func(d *service.Descr, value []byte) ([]byte, error) {
		log.Warnf("GOT WRITE REQUEST")
		return value, nil
	})

	err = char1.AddDescr(descr1)
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

var SENDER_CERT = `-----BEGIN CERTIFICATE-----
MIIDvzCCAaegAwIBAgIBBTANBgkqhkiG9w0BAQsFADCBozELMAkGA1UEBhMCRkkx
GjAYBgNVBAgMEVBvaGpvaXMtUG9oamFubWFhMQ0wCwYDVQQHDARPdWx1MRswGQYD
VQQKDBJVbml2ZXJzaXR5IG9mIE91bHUxDjAMBgNVBAsMBU9VU1BHMRYwFAYDVQQD
DA1TZWNyZWRhcyBUZXN0MSQwIgYJKoZIhvcNAQkBFhVqYXJpLmphYXNrZWxhQG91
bHUuZmkwIBcNMjAwNzAzMDkzNzEyWhgPMjI5NDA0MTcwOTM3MTJaMA8xDTALBgNV
BAMMBHRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAShtlV69CWX2nz1ohIc
as8NlCfvJUcruYwbXcqSTiH/xqNH4psSw6VMEL6S+h7058tZCVjTI5mXPgB5UnZZ
3gi3o1owWDAdBgNVHQ4EFgQUCIFV92S8UarKCC3aLKDGyD08790wHwYDVR0jBBgw
FoAU7w7HriCjtXYFMuO94QPooGtgfnwwCQYDVR0TBAIwADALBgNVHQ8EBAMCBaAw
DQYJKoZIhvcNAQELBQADggIBAF8XtVsutVcPTkJjZwLHPAeVN8ObwlEBKfJU2hIw
G32ebC2PkHV0G3KewZ6rGk90JjFCj+0ulKI0BOTSokzgOM4EmuFYbKSrifYuRlUf
jXr+b7Va8eu65pXoyaH8nK8JTwj88kPjYBc3jAkfpWPis00TINbxOJHIiiP6xFOy
Xyq7Els9trZRooOwqPjH5pyKC+54U5myGHyfTBHf70TzpLmSe8inw1KfQZ3xlsXb
P6NLq1VY4RKquvGTUa85aIt46yXqN7Hs4QW9JwsfhrrXlkuhnJm2YMjInQq43P1i
U9IsIKTtlrexDSm1UdhxAU+78EB4CH65ugK/T91BKpEyWqP/ERlZyjC5y6pcTlKt
6ePdXQmPYMMOQkEQHDdtO22lya9n9rMcJhLg5kt7ARGlEXwn1FfVzSfn13aPxJXW
AoAp7vsEgCNVWuvqBWW4VZoEBZSXRwQvVeZQMmj5X+6ug/crtWdR/mopgBX4RROJ
3i15O+NxBn/3SHbQpc/+GI66AQ7LspX3id8/atUj/fL7c7hOIIrSLdm0lNf3aQNe
B35IecoasuSeKbT+wrkMoje/YhVg++/2w+O+4lUT0CUWQnwJyhYv9dutcyTBt8mY
Hn6uAeg1EElZLRQ/55MfXZBmqiwtbNatm8bZClaBuTBwx8ytRI9do1wlhvBUQp5C
wIRp
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
func CreateKeyExchangeService(adapterID string, certificate []byte) error {
	btmgmt := hw.NewBtMgmt(adapterID)
	if len(os.Getenv("DOCKER")) > 0 {
		btmgmt.BinPath = "./bin/docker-btmgmt"
	}

	// set LE mode
	btmgmt.SetPowered(false)

	btmgmt.SetLe(true)
	btmgmt.SetBondable(false)
	btmgmt.SetLinkLevelSecurity(false)
	btmgmt.SetPairable(true)
	btmgmt.SetConnectable(true)
	btmgmt.SetSsp(false)
	btmgmt.SetBredr(false)

	btmgmt.SetPowered(true)

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

	a.SetName("secredas exchange")

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
		log.Info("GOT READ 1 CERTIFICATE REQUEST")
		log.Print(options)
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
		log.Info("GOT READ 2 CERTIFICATE REQUEST")
		log.Print(options)
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
		log.Info("GOT READ 3 CERTIFICATE REQUEST")
		log.Print(options)
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

		responseData, err := MarshalECDHExchange(ECDHExchange{
			Signature: nil,
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

	tokenExchangeChar, err := service1.NewChar(TOKEN_EXC_CHAR_UUID)
	if err != nil {
		return err
	}

	tokenExchangeChar.Properties.Flags = []string{
		gatt.FlagCharacteristicWrite, gatt.FlagCharacteristicRead,
	}


	var tokenRes []byte
	tokenExchangeChar.OnRead(func(c *service.Char, options map[string]interface{}) (bytes []byte, err error) {
		return tokenRes, nil
	})

	tokenExchangeChar.OnWrite(func(c *service.Char, value []byte) (bytes []byte, err error) {

		ciphertext, err := crypto.UnmarshalNoncedCiphertext(value)
		if err != nil {
			log.Fatalf("Could not unmarshal ciphertext: %s", ciphertext)
		}

		plaintext, err := cipherSession.Decrypt(ciphertext)
		if err != nil {
			log.Fatalf("Could not decrypt ciphertext: %s", err)
		}

		log.Printf("Token received: %s\n", plaintext)

		respCiphertext, err := cipherSession.Encrypt([]byte("token"))
		if err != nil {
			log.Fatalf("Could not encrypt response token: %s", err)
		}

		res, err := crypto.MarshalNoncedCiphertext(respCiphertext)
		if err != nil {
			log.Fatalf("Could not marshal response token ciphertext: %s", err)
		}
		tokenRes = res
		return
	})

	err = service1.AddChar(tokenExchangeChar)
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
