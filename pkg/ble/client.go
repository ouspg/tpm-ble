package ble

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jarijaas/openssl"
	"github.com/muka/go-bluetooth/api"
	"github.com/muka/go-bluetooth/bluez/profile/adapter"
	"github.com/muka/go-bluetooth/bluez/profile/device"
	"github.com/muka/go-bluetooth/bluez/profile/gatt"
	"github.com/ouspg/tpm-ble/pkg/btmgmt"
	"github.com/ouspg/tpm-ble/pkg/crypto"
	log "github.com/sirupsen/logrus"
	"strings"
	"time"
)

/**
https://github.com/muka/go-bluetooth/blob/master/examples/service/client.go
 */

func discover(a *adapter.Adapter1, hwaddr string) (*device.Device1, error) {

	err := a.FlushDevices()
	if err != nil {
		return nil, err
	}

	filter := adapter.DiscoveryFilter{
		Transport:     "le",
	}

	discovery, cancel, err := api.Discover(a, &filter)
	if err != nil {
		return nil, err
	}

	defer cancel()

	log.Info("Iterate discovered devices")

	for ev := range discovery {

		dev, err := device.NewDevice1(ev.Path)
		if err != nil {
			return nil, err
		}

		if dev == nil || dev.Properties == nil {
			continue
		}

		p := dev.Properties

		n := p.Alias
		if p.Name != "" {
			n = p.Name
		}

		log.Infof("Discovered (%s) %s", n, p.Address)
		log.Printf("UUIDs: %s\n", p.UUIDs)

		if n != hwaddr && p.Address != hwaddr {
			continue
		}
		return dev, nil
	}

	return nil, nil
}

func findDevice(a *adapter.Adapter1, hwaddr string) (*device.Device1, error) {
	dev, err := discover(a, hwaddr)
	if err != nil {
		return nil, err
	}
	if dev == nil {
		return nil, errors.New("Device not found, is it advertising?")
	}

	return dev, nil
}

func client(adapterID, hwaddr string) (dev *device.Device1, err error) {
	log.Infof("Discovering %s on %s", hwaddr, adapterID)

	a, err := adapter.NewAdapter1FromAdapterID(adapterID)
	if err != nil {
		return nil, err
	}

	dev, err = findDevice(a, hwaddr)
	if err != nil {
		return nil, fmt.Errorf("findDevice: %s", err)
	}

	watchProps, err := dev.WatchProperties()
	if err != nil {
		return nil, err
	}
	go func() {
		for propUpdate := range watchProps {
			log.Debugf("--> updated %s=%v", propUpdate.Name, propUpdate.Value)
		}
	}()

	log.Info("Found device, connect")

	err = connect(dev)
	if err != nil {
		return nil, err
	}

	log.Info("retrieveServices")
	retrieveServices(a, dev)
	return dev, nil
}

func connect(dev *device.Device1) error {

	props, err := dev.GetProperties()
	if err != nil {
		return fmt.Errorf("Failed to load props: %s", err)
	}

	log.Infof("Found device name=%s addr=%s rssi=%d", props.Name, props.Address, props.RSSI)

	if props.Connected {
		log.Trace("Device is connected")
		return nil
	}

	if !props.Connected {
		log.Trace("Connecting device")
		err = dev.Connect()
		if err != nil {
			if !strings.Contains(err.Error(), "Connection refused") {
				return fmt.Errorf("Connect failed: %s", err)
			}
		}
	}

	log.Infof("Connected")

	return nil
}

func retrieveServices(a *adapter.Adapter1, dev *device.Device1) error {

	log.Debug("Listing exposed services")

	list, err := dev.GetAllServicesAndUUID()
	if err != nil {
		return err
	}

	if len(list) == 0 {
		time.Sleep(time.Second * 2)
		return retrieveServices(a, dev)
	}

	for _, servicePath := range list {
		log.Infof("%s", servicePath)
	}

	return nil
}

func ReadCharacteristic(dev *device.Device1, charUUID string) ([]byte, error) {
	log.Printf("Find Char UUID: %s\n", charUUID)

	list, err := dev.GetCharacteristicsList()
	if err != nil {
		return nil, err
	}

	if len(list) == 0 {
		time.Sleep(time.Second * 2)
		return ReadCharacteristic(dev, charUUID)
	}

	char, err := dev.GetCharByUUID(charUUID)
	if err != nil {
		return nil, err
	}

	data, err := char.ReadValue(nil)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func StartCharacteristicNotify(dev *device.Device1, charUUID string) (chan []byte, error) {
	list, err := dev.GetCharacteristicsList()
	if err != nil {
		return nil, err
	}

	if len(list) == 0 {
		time.Sleep(time.Second * 2)
		return StartCharacteristicNotify(dev, charUUID)
	}

	char, err := dev.GetCharByUUID(charUUID)
	if err != nil {
		return nil, err
	}

	err = char.StartNotify()
	if err != nil {
		return nil, err
	}

	inCh, err := char.WatchProperties()
	if err != nil {
		return nil, err
	}

	outCh := make(chan []byte, 1)

	go func() {
		for {
			val, more := <- inCh
			outCh <- val.Value.([]byte)

			if !more {
				close(outCh)
				return
			}
		}
	}()

	return outCh, err
}

func writeCharacteristicWithResponse(dev *device.Device1, charUUID string, value []byte) ([]byte, error) {
	list, err := dev.GetCharacteristicsList()
	if err != nil {
		return nil, err
	}

	if len(list) == 0 {
		time.Sleep(time.Second * 2)
		return writeCharacteristicWithResponse(dev, charUUID, value)
	}

	for _, path := range list {
		char, err := gatt.NewGattCharacteristic1(path)
		if err != nil {
			return nil, err
		}

		cuuid := strings.ToUpper(char.Properties.UUID)
		log.Printf("Found Char UUID: %s\n", cuuid)
	}

	char, err := dev.GetCharByUUID(charUUID)
	if err != nil {
		return nil, err
	}

	err = char.WriteValue(value, map[string]interface{}{
		"type": "request",
	})
	if err != nil {
		return nil, err
	}

	res, err := char.ReadValue(nil)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func CreateConnection(adapterID string, hwaddr string) (*device.Device1, error) {
	dev, err := client(adapterID, hwaddr)
	return dev, err
}

type SecureDevice struct {
	Dev *device.Device1
	CipherSession *crypto.CipherSession
}

func CreateSecureConnection(caPath string, cert []byte, privKeyPath string, adapterID string, hwaddr string) (*SecureDevice, error) {
	dev, err := client(adapterID, hwaddr)
	if err != nil {
		return nil, err
	}

	pemCert, err := ReadCertificate(dev)
	if err != nil {
		return nil, fmt.Errorf("could not read certificate. Error: %s", err)
	}

	log.Printf("Certificate: \n%s\n", string(pemCert))

	log.Println("Verify certificate")

	err = crypto.VerifyCertificate(caPath, pemCert)
	if err != nil {
		log.Fatalf("Could not verify certificate. Error: %s", err)
	}

	serverCert, err := openssl.LoadCertificateFromPEM(pemCert)
	if err != nil {
		return nil, fmt.Errorf("could not read cert: %s", err)
	}
	serverPub, err := serverCert.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("could not read public key: %s", err)
	}

	log.Println("Certificate was deemed valid (signed by the CA)")

	err = WriteCertificate(dev, cert)
	if err != nil {
		return nil, fmt.Errorf("could not send certificate: %s", err)
	}

	signingPrivKey, err := crypto.LoadTPMPrivateKey(privKeyPath)
	if err != nil {
		return nil, fmt.Errorf("could not load TPM private key used in signing: %s", err)
	}

	ephKey, err := crypto.GenECDHPrivKey()
	if err != nil {
		return nil, fmt.Errorf("could not generate ephemeral key for ECDH: %s", err)
	}

	pubKeyBytes := crypto.ECCPubKeyToBytes(&ephKey.PublicKey)
	log.Printf("Sign: %s\n", hex.EncodeToString(pubKeyBytes))

	pubKeySig, err := crypto.Sign(signingPrivKey, pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("´could not sign ECDH pub key: %s", err)
	}

	log.Printf("ECDH pub key signature: %s", hex.EncodeToString(pubKeySig))

	log.Printf("Send ECDH pub key, certificate and the signature to the other party")

	clientRand := SecRand32Bytes()

	exchangeResponse, err := BeginECDHExchange(dev, ECDHExchange{
		Signature: pubKeySig,
		PubKey:    pubKeyBytes,
		Random:	   clientRand,
	})
	if err != nil {
		return nil, fmt.Errorf("ECDH exchange failed: %s", err)
	}

	log.Printf("Received pub key (key, sig): (%s, %s)",
		hex.EncodeToString(exchangeResponse.PubKey), hex.EncodeToString(exchangeResponse.Signature))

	log.Println("Verify signature")
	err = crypto.Verify(serverPub, exchangeResponse.PubKey, exchangeResponse.Signature)
	if err != nil {
		return nil, fmt.Errorf("server public key signature is not valid: %s", err)
	}

	serverPubKey := crypto.BytesToECCPubKey(exchangeResponse.PubKey)

	sessionKey := crypto.ComputeSessionKey(serverPubKey, ephKey, clientRand, exchangeResponse.Random)
	log.Printf("Session key: %s\n", hex.EncodeToString(sessionKey[:]))

	cipherSession, err := crypto.NewCipherSession(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("could not create cipher session: %s", err)
	}

	return &SecureDevice{
		Dev:           dev,
		CipherSession: cipherSession,
	}, nil
}

func (secDev *SecureDevice) SecureReadCharacteristic(charUUID string) ([]byte, error) {
	data, err := ReadCharacteristic(secDev.Dev, charUUID)
	if err != nil {
		return nil, err
	}

	ciphertext, err := crypto.UnmarshalNoncedCiphertext(data)
	if err != nil {
		log.Fatalf("Could not unmarshal ciphertext: %s", ciphertext)
		return nil, fmt.Errorf("could not unmarshal ciphertext: %s", ciphertext)
	}

	plaintext, err := secDev.CipherSession.Decrypt(ciphertext)
	if err != nil {
		log.Fatal(err)
		return nil, fmt.Errorf("could not decrypt ciphertext: %s", err)
	}
	return plaintext, nil
}

func (secDev *SecureDevice) StartSecureCharacteristicNotify(charUUID string) (chan []byte, error) {

	inCh, err := StartCharacteristicNotify(secDev.Dev, charUUID)
	if err != nil {
		return nil, err
	}

	outCh := make(chan []byte, 1)

	go func() {
		for {
			val, more := <- inCh

			ciphertext, err := crypto.UnmarshalNoncedCiphertext(val)
			if err != nil {
				log.Warnf("could not unmarshal ciphertext: %s", ciphertext)
				continue
			}

			plaintext, err := secDev.CipherSession.Decrypt(ciphertext)
			if err != nil {
				log.Warnf("could not decrypt ciphertext: %s", err)
				continue
			}

			outCh <- plaintext

			if !more {
				close(outCh)
				return
			}
		}
	}()

	return outCh, nil
}

func (secDev *SecureDevice) SecureWriteCharacteristic(charUUID string, data []byte, options map[string]interface{}) error {
	list, err := secDev.Dev.GetCharacteristicsList()
	if err != nil {
		return err
	}

	if len(list) == 0 {
		time.Sleep(time.Second * 2)
		return secDev.SecureWriteCharacteristic(charUUID, data, options)
	}

	char, err := secDev.Dev.GetCharByUUID(charUUID)
	if err != nil {
		return err
	}

	ciphertext, err := secDev.CipherSession.Encrypt(data)
	if err != nil {
		return err
	}

	data, err = crypto.MarshalNoncedCiphertext(ciphertext)
	if err != nil {
		return err
	}

	err = char.WriteValue(data, options)
	if err != nil {
		return err
	}
	return nil
}


func WriteCertificate(dev *device.Device1, cert []byte) error {
	list, err := dev.GetCharacteristicsList()
	if err != nil {
		return err
	}

	if len(list) == 0 {
		time.Sleep(time.Second * 2)
		return WriteCertificate(dev, cert)
	}

	char, err := dev.GetCharByUUID(WRITE_CERT_CHAR_UUID + APP_UUID_SUFFIX)
	if err != nil {
		return err
	}

	const chunkSize = 500

	for off := 0; off < len(cert); off += chunkSize {
		endOff := off + chunkSize
		if endOff >= len(cert) {
			endOff = len(cert)
		}

		err = char.WriteValue(cert[off:endOff], map[string]interface{}{
			"type": "request",
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func ReadCertificate(dev *device.Device1) ([]byte, error) {
	var pemCert []byte

	// Hmm. probably write characteristic could be used also
	chunk, err := ReadCharacteristic(dev, READ_CERT_1_CHAR_UUID +APP_UUID_SUFFIX)
	if err != nil {
		log.Fatal(err)
	}
	pemCert = append(pemCert, chunk ...)

	chunk, err = ReadCharacteristic(dev, READ_CERT_2_CHAR_UUID +APP_UUID_SUFFIX)
	if err != nil {
		log.Fatal(err)
	}
	pemCert = append(pemCert, chunk ...)

	chunk, err = ReadCharacteristic(dev, READ_CERT_3_CHAR_UUID +APP_UUID_SUFFIX)
	if err != nil {
		log.Fatal(err)
	}
	pemCert = append(pemCert, chunk ...)

	return pemCert, nil
}

func BeginECDHExchange(dev *device.Device1, data ECDHExchange) (*ECDHExchange, error) {
	exchangeData, err := MarshalECDHExchange(data)
	if err != nil {
		return nil, fmt.Errorf("could not marshal ECDH data: %s", err)
	}

	log.Println(string(exchangeData))

	res, err := writeCharacteristicWithResponse(dev, ECDH_EXC_CHAR_UUID +APP_UUID_SUFFIX, exchangeData)
	if err != nil {
		return nil, fmt.Errorf("could not write to characteristic: %s", err)
	}
	return UnmarshalECDHExchange(res)
}


func ExchangeOOBData(dev *device.Device1, cipherSession *crypto.CipherSession, adapterAddr string) (*OOBExchange, error) {
	h192, r192, h256, r256, err := btmgmt.ReadLocalOOBDataExtended(0)
	if err != nil {
		log.Fatalf("Could not read local oob data: %s", err)
	}

	log.Printf("Local OOB data (h192, r192, h256, r256): (%s, %s, %s, %s)",
		hex.EncodeToString(h192[:]), hex.EncodeToString(r192[:]),
		hex.EncodeToString(h256[:]), hex.EncodeToString(r256[:]))

	oobData := [32]byte{}
	copy(oobData[:16], h256[:])
	copy(oobData[16:], r256[:])

	log.Printf("The adapter the OOB pairing is done for: %s\n", adapterAddr)

	data, err := MarshalOOBExchange(OOBExchange{
		Data:    oobData,
		Address: adapterAddr,
	})
	if err != nil {
		return nil, fmt.Errorf("could not mashal oob exhange data")
	}

	ciphertext, err := cipherSession.Encrypt(data)
	if err != nil {
		return nil, err
	}

	data, err = crypto.MarshalNoncedCiphertext(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("could not marshal nonced ciphertext: %s", err)
	}

	res, err := writeCharacteristicWithResponse(dev, OOB_EXC_CHAR_UUID +APP_UUID_SUFFIX, data)
	if err != nil {
		return nil, fmt.Errorf("could not write to characteristic: %s", err)
	}

	resp, err := crypto.UnmarshalNoncedCiphertext(res)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal response nonced ciphertext: %s", err)
	}

	plaintext, err := cipherSession.Decrypt(resp)
	if err != nil {
		return nil, err
	}

	recvExchangeData := OOBExchange{}
	err = json.Unmarshal(plaintext, &recvExchangeData)
	return &recvExchangeData, err
}