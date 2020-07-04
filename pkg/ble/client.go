package ble

import (
	"errors"
	"fmt"
	"github.com/godbus/dbus/v5"
	"github.com/muka/go-bluetooth/api"
	"github.com/muka/go-bluetooth/bluez/profile/adapter"
	"github.com/muka/go-bluetooth/bluez/profile/agent"
	"github.com/muka/go-bluetooth/bluez/profile/device"
	"github.com/muka/go-bluetooth/bluez/profile/gatt"
	log "github.com/sirupsen/logrus"
	"strings"
	"time"
	"github.com/ouspg/tpm-bluetooth/pkg/crypto"
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

		log.Info("Found device")

		return dev, nil
	}

	return nil, nil
}

func findDevice(a *adapter.Adapter1, hwaddr string) (*device.Device1, error) {
	//
	// devices, err := a.GetDevices()
	// if err != nil {
	// 	return nil, err
	// }
	//
	// for _, dev := range devices {
	// 	devProps, err := dev.GetProperties()
	// 	if err != nil {
	// 		log.Errorf("Failed to load dev props: %s", err)
	// 		continue
	// 	}
	//
	// 	log.Info(devProps.Address)
	// 	if devProps.Address != hwaddr {
	// 		continue
	// 	}
	//
	// 	log.Infof("Found cached device Connected=%t Trusted=%t Paired=%t", devProps.Connected, devProps.Trusted, devProps.Paired)
	// 	return dev, nil
	// }

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

	//Connect DBus System bus
	conn, err := dbus.SystemBus()
	if err != nil {
		return nil, err
	}

	// do not reuse agent0 from service
	agent.NextAgentPath()

	ag := agent.NewSimpleAgent()
	err = agent.ExposeAgent(conn, ag, agent.CapNoInputNoOutput, true)
	if err != nil {
		return nil, fmt.Errorf("SimpleAgent: %s", err)
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

	err = connect(dev, ag, adapterID)
	if err != nil {
		return nil, err
	}

	// log.Info("retrieveServices")
	retrieveServices(a, dev)
	return dev, nil

	// select {}

	// return nil
}

func connect(dev *device.Device1, ag *agent.SimpleAgent, adapterID string) error {

	props, err := dev.GetProperties()
	if err != nil {
		return fmt.Errorf("Failed to load props: %s", err)
	}

	log.Infof("Found device name=%s addr=%s rssi=%d", props.Name, props.Address, props.RSSI)

	if props.Connected {
		log.Trace("Device is connected")
		return nil
	}

	/*if !props.Paired || !props.Trusted {
		log.Trace("Pairing device")

		err := dev.Pair()
		if err != nil {
			return fmt.Errorf("Pair failed: %s", err)
		}

		log.Info("Pair succeed, connecting...")
		agent.SetTrusted(adapterID, dev.Path())
	}*/

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

func readCharacteristic(dev *device.Device1, charUUID string) ([]byte, error) {
	log.Printf("Find Char UUID: %s\n", charUUID)

	list, err := dev.GetCharacteristicsList()
	if err != nil {
		return nil, err
	}

	if len(list) == 0 {
		time.Sleep(time.Second * 2)
		return readCharacteristic(dev, charUUID)
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

	data, err := char.ReadValue(nil)
	if err != nil {
		return nil, err
	}

	log.Println(string(data))
	// log.Println(hex.Dump(data))

	return data, nil
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


func ReadCertificate(dev *device.Device1) ([]byte, error) {
	var pemCert []byte

	/*_, err = readCharacteristic(adapterID, SERVICE_UUID, READ_CERT_CHAR_UUID)
	if err != nil {
		return err
	}*/

	// Hmm. probably write characteristic could be used also
	chunk, err := readCharacteristic(dev, READ_CERT_1_CHAR_UUID + UUID_SUFFIX)
	if err != nil {
		log.Fatal(err)
	}
	pemCert = append(pemCert, chunk ...)

	chunk, err = readCharacteristic(dev, READ_CERT_2_CHAR_UUID + UUID_SUFFIX)
	if err != nil {
		log.Fatal(err)
	}
	pemCert = append(pemCert, chunk ...)

	chunk, err = readCharacteristic(dev, READ_CERT_3_CHAR_UUID + UUID_SUFFIX)
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

	res, err := writeCharacteristicWithResponse(dev, ECDH_EXC_CHAR_UUID + UUID_SUFFIX, exchangeData)
	if err != nil {
		return nil, fmt.Errorf("could not write to characteristic: %s", err)
	}
	return UnmarshalECDHExchange(res)
}


func ExchangeTokens(dev *device.Device1, cipherSession *crypto.CipherSession) ([]byte, error) {
	token := []byte("token")

	ciphertext, err := cipherSession.Encrypt(token)
	if err != nil {
		return nil, err
	}

	data, err := crypto.MarshalNoncedCiphertext(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("could not marshal nonced ciphertext: %s", err)
	}

	res, err := writeCharacteristicWithResponse(dev, TOKEN_EXC_CHAR_UUID + UUID_SUFFIX, data)
	if err != nil {
		return nil, fmt.Errorf("could not write to characteristic: %s", err)
	}

	resp, err := crypto.UnmarshalNoncedCiphertext(res)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal response nonced ciphertext: %s", err)
	}

	return cipherSession.Decrypt(resp)
}