package ble

import (
	"github.com/muka/go-bluetooth/api/service"
	"github.com/muka/go-bluetooth/bluez/profile/agent"
	"github.com/muka/go-bluetooth/bluez/profile/gatt"
	"github.com/muka/go-bluetooth/hw"
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

const CHAR_CHUNK_SIZE = 500

/**
Max char dat len is 512 bytes, simplest solution is to use multiple characteristic to deliver the data
Alternatively, sign only the pub key and deliver that only instead of the whole certificate
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

	/*certChar2, err := service1.NewChar(READ_CERT_2_CHAR_UUID)
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
		return certificate[2 * CHAR_CHUNK_SIZE:3 * CHAR_CHUNK_SIZE], nil
	})

	err = service1.AddChar(certChar3)
	if err != nil {
		return err
	}*/

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
