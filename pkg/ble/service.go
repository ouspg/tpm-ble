package ble

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"github.com/godbus/dbus/v5"
	"github.com/jarijaas/openssl"
	"github.com/muka/go-bluetooth/api/service"
	"github.com/muka/go-bluetooth/bluez"
	"github.com/muka/go-bluetooth/bluez/profile/agent"
	"github.com/muka/go-bluetooth/bluez/profile/device"
	"github.com/muka/go-bluetooth/bluez/profile/gatt"
	btmgmt2 "github.com/ouspg/tpm-ble/pkg/btmgmt"
	"github.com/ouspg/tpm-ble/pkg/crypto"
	log "github.com/sirupsen/logrus"
	"os"
)

const CHAR_CHUNK_SIZE = 500

var ephPrivKey *ecdsa.PrivateKey

/**
Max char dat len is 512 bytes, simplest solution is to use multiple characteristic to deliver the data
gatt also supports long characteristics (over 512 bytes) but the dbus api does not seem to implement support for that
Alternatively, sign only the pub key and deliver that only instead of the whole certificate
 */

const MY_SECURE_BLE_HWADDR = "DC:A6:32:35:EF:E2"

func onConnectionChange(adapterId string, cbConn func(dev *device.Device1), cbDisconn func(dev *device.Device1)) {
	conn, err := dbus.SystemBus()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to connect to session bus:", err)
		os.Exit(1)
	}

	if err = conn.AddMatchSignal(
		dbus.WithMatchPathNamespace(dbus.ObjectPath(fmt.Sprintf("%s/%s", bluez.OrgBluezPath, adapterId))),
		dbus.WithMatchInterface(bluez.PropertiesInterface),
		dbus.WithMatchMember("PropertiesChanged"),
	); err != nil {
		panic(err)
	}

	c := make(chan *dbus.Signal, 1)
	conn.Signal(c)

	go func() {
		for v := range c {
			propInterface := v.Body[0].(string)
			propMap := v.Body[1].(map[string]dbus.Variant)

			if propInterface == "org.bluez.Device1" {
				dev, err := device.NewDevice1(v.Path)
				if err != nil {
					log.Fatalf("Could not create device from object path: %s", err)
				}

				if connected, ok := propMap["Connected"]; ok {
					if connected.Value().(bool) {
						cbConn(dev)
					} else {
						cbDisconn(dev)
					}
				}
			}
		}
	}()
}

func CreateKeyExchangeService(secApp *SecureApp, caPath string, certificate []byte, privKeyPem []byte) error {
	app := secApp.App

	privKey, err := openssl.LoadPrivateKeyFromPEM(privKeyPem)
	if err != nil {
		return fmt.Errorf("could not load private key: %s", err)
	}

	service1, err := app.NewService(KEY_EXC_SERVICE_UUID)
	if err != nil {
		return err
	}

	err = app.AddService(service1)
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


	clientCertChar, err := service1.NewChar(WRITE_CERT_CHAR_UUID)
	if err != nil {
		return err
	}

	clientCertChar.Properties.Flags = []string{
		gatt.FlagCharacteristicWrite,
	}

	clientCertChar.OnWrite(func(c *service.Char, value []byte) (bytes []byte, err error) {
		secApp.ClientConn.clientCertificate = append(secApp.ClientConn.clientCertificate, value ...)
		return nil, nil
	})

	err = service1.AddChar(clientCertChar)
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
	This is not really the best way to send response to write request, but it is unclear how
	write request response should be read
	*/
	ecdhExchangeChar.OnRead(func(c *service.Char, options map[string]interface{}) (bytes []byte, err error) {
		return secApp.ClientConn.exchangeRes, nil
	})

	ecdhExchangeChar.OnWrite(func(c *service.Char, value []byte) ([]byte, error) {
		log.Debug("GOT ECDH WRITE REQUEST")

		exchangeData, err := UnmarshalECDHExchange(value)
		if err != nil {
			log.Fatalf("Could not unmarshal received ECDH exchange data: %s", err)
		}

		log.Printf("Received ECDH public key (key, sig): (%s, %s)\n",
			hex.EncodeToString(exchangeData.PubKey), hex.EncodeToString(exchangeData.Signature))

		err = crypto.VerifyCertificate(caPath, secApp.ClientConn.clientCertificate)
		if err != nil {
			log.Fatalf("Could not verify certificate. Error: %s", err)
		}

		clientCert, err := openssl.LoadCertificateFromPEM(secApp.ClientConn.clientCertificate)
		if err != nil {
			log.Fatalf("Could not load pub key from PEM: %s", err)
		}

		pubKey, err := clientCert.PublicKey()
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
		log.Debugf("Client pubKeyX: %s", originatorPubKey.X.String())
		log.Debugf("Client pubKeyY: %s", originatorPubKey.Y.String())

		sessionKey := crypto.ComputeSessionKey(originatorPubKey, ephPrivKey)
		log.Printf("Session key: %s", hex.EncodeToString(sessionKey))

		secApp.ClientConn.cipherSession, err = crypto.NewCipherSession(sessionKey)
		if err != nil {
			log.Fatalf("Could not create session cipher: %s", err)
		}
		secApp.ClientConn.isSecure = true

		secApp.ClientConn.exchangeRes = responseData
		return responseData, nil
	})

	err = service1.AddChar(ecdhExchangeChar)
	if err != nil {
		return err
	}
	return nil
}

func (secApp *SecureApp) OnWriteSecure(char *service.Char, fx service.CharWriteCallback) {
	char.OnWrite(func(c *service.Char, value []byte) (bytes []byte, err error) {
		if !secApp.ClientConn.isSecure {
			log.Warn("Received secure write request on unsecured connection")
			return nil, nil
		}

		ciphertext, err := crypto.UnmarshalNoncedCiphertext(value)
		if err != nil {
			log.Fatalf("Could not unmarshal ciphertext: %s", ciphertext)
		}

		plaintext, err := secApp.ClientConn.cipherSession.Decrypt(ciphertext)
		if err != nil {
			log.Fatalf("Could not decrypt ciphertext: %s", err)
		}

		return fx(c, plaintext)
	})
}

func (secApp *SecureApp) OnReadSecure(char *service.Char, fx service.CharReadCallback) {
	char.OnRead(func(c *service.Char, options map[string]interface{}) (bytes []byte, err error) {
		if !secApp.ClientConn.isSecure {
			log.Warn("Received secure read request on unsecured connection")
			return nil, nil
		}

		plaintext, err := fx(c, options)
		if err != nil {
			return nil, err
		}

		ciphertext, err := secApp.ClientConn.cipherSession.Encrypt(plaintext)
		if err != nil {
			log.Fatalf("Could not encrypt response data: %s", err)
		}

		res, err := crypto.MarshalNoncedCiphertext(ciphertext)
		if err != nil {
			log.Fatalf("Could not marshal response data ciphertext: %s", err)
		}
		return res, err
	})
}

func (secApp *SecureApp) Advertise(timeout uint32) error {
	var err error
	secApp.CancelAdvertise()

	secApp.advCancel, err = secApp.App.Advertise(timeout)
	return err
}

func (secApp *SecureApp) CancelAdvertise() {
	secApp.advCancel()
	secApp.advCancel = func() {}
}

func CreateOOBDataExchangeService(secApp *SecureApp) error {
	app := secApp.App

	myH192, myR192, myH256, myR256, err := btmgmt2.ReadLocalOOBDataExtended(0)
	if err != nil {
		return fmt.Errorf("could not read local oob data: %s", err)
	}

	log.Debugf("Local OOB data (h192, r192, h256, r256): (%s, %s, %s, %s)",
		hex.EncodeToString(myH192[:]), hex.EncodeToString(myR192[:]),
		hex.EncodeToString(myH256[:]), hex.EncodeToString(myR256[:]))

	service1, err := app.NewService(OOB_EXC_SERVICE_UUID)
	if err != nil {
		return err
	}

	err = app.AddService(service1)
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

	secApp.OnReadSecure(oobExchangeChar, func(c *service.Char, options map[string]interface{}) (bytes []byte, err error) {
		if !secApp.ClientConn.isSecure {
			return nil, nil
		}

		return secApp.ClientConn.oobDataRes, nil
	})

	secApp.OnWriteSecure(oobExchangeChar, func(c *service.Char, value []byte) (bytes []byte, err error) {
		log.Infof("OOB data received: %s\n", value)

		oobExchange, err := UnmarshalOOBExchange(value)
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

		secApp.ClientConn.oobDataRes, err = MarshalOOBExchange(OOBExchange{
			Data:    oobData,
			Address: MY_SECURE_BLE_HWADDR,
		})
		return
	})

	err = service1.AddChar(oobExchangeChar)
	if err != nil {
		return err
	}
	return nil
}

// Send secure notification / indication
func (secApp *SecureApp) SecureWrite(char *service.Char, value []byte, options map[string]interface{}) error {
	if secApp.ClientConn == nil || !secApp.ClientConn.isSecure {
		return nil
	}

	ciphertext, err := secApp.ClientConn.cipherSession.Encrypt(value)
	if err != nil {
		return err
	}

	value, err = crypto.MarshalNoncedCiphertext(ciphertext)
	if err != nil {
		return err
	}
	return char.WriteValue(value, options)
}


const AdvertiseForever = 0xFFFFFFFF

type SecureApp struct {
	ClientConn *ClientConnection
	App *service.App
	advCancel func()
}

func NewSecureApp(options service.AppOptions) (*SecureApp, error) {
	app, err := service.NewApp(options)
	if err != nil {
		return nil, err
	}

	secApp := &SecureApp{
		ClientConn: nil,
		App:        app,
		advCancel: func() {},
	}

	// Only one client can connect at a time
	onConnectionChange(options.AdapterID, func(dev *device.Device1) {
		addr, err := dev.GetAddress()
		if err != nil {
			log.Fatal(err)
		}

		secApp.ClientConn = NewClientConnection()
		secApp.ClientConn.dev = dev
		secApp.ClientConn.hwAddr = addr
	}, func(dev *device.Device1) {
		if secApp.ClientConn != nil {
			secApp.ClientConn.Close()
			secApp.ClientConn = nil
		}

		// For some reason after connection, advertising stops so start advertising again when the client disconnects
		secApp.Advertise(AdvertiseForever)
	})

	return secApp, nil
}

func CreateOOBDataExchangeApp(adapterID string, caPath string, cert []byte, privKey []byte) (*SecureApp, error) {
	options := service.AppOptions{
		AdapterID:  adapterID,
		AgentCaps:  agent.CapNoInputNoOutput,
		UUIDSuffix: APP_UUID_SUFFIX,
		UUID:       APP_UUID,
	}

	secApp, err := NewSecureApp(options)
	if err != nil {
		return nil, err
	}
	app := secApp.App

	app.SetName("OOB exchange")

	if !app.Adapter().Properties.Powered {
		err = app.Adapter().SetPowered(true)
		if err != nil {
			log.Fatalf("Failed to power the adapter: %s", err)
		}
	}

	err = CreateKeyExchangeService(secApp, caPath, cert, privKey)
	if err != nil {
		return nil, err
	}

	err = CreateOOBDataExchangeService(secApp)
	if err != nil {
		return nil, err
	}

	return secApp, nil
}
