package main

import (
	"github.com/muka/go-bluetooth/api/service"
	"github.com/muka/go-bluetooth/bluez/profile/agent"
	"github.com/muka/go-bluetooth/bluez/profile/gatt"
	log "github.com/sirupsen/logrus"
	"time"
)

const UUID_SUFFIX = "-0000-1000-8000-00905F9B34FB"
const APP_UUID = "0001"
const SERVICE_UUID = "0001"

const SECURE_CHAR_UUID = "00000001"

func main() {

	options := service.AppOptions{
		AdapterID:  "hci0",
		AgentCaps:  agent.CapNoInputNoOutput,
		UUIDSuffix: UUID_SUFFIX,
		UUID: APP_UUID,
	}

	a, err := service.NewApp(options)
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()

	a.SetName("Secure")

	if !a.Adapter().Properties.Powered {
		err = a.Adapter().SetPowered(true)
		if err != nil {
			log.Fatalf("Failed to power the adapter: %s", err)
		}
	}

	service1, err := a.NewService(SERVICE_UUID)
	if err != nil {
		log.Fatal(err)
	}

	secureChar, err := service1.NewChar(SECURE_CHAR_UUID)
	if err != nil {
		log.Fatal(secureChar)
	}

	secureChar.Properties.Flags = []string{
		// gatt.FlagCharacteristicEncryptAuthenticatedRead,
		gatt.FlagCharacteristicEncryptRead,
	}

	secureChar.OnRead(func(c *service.Char, options map[string]interface{}) ([]byte, error) {
		return []byte("This data can be read after OOB pairing"), nil
	})

	err = a.AddService(service1)
	if err != nil {
		log.Fatal(err)
	}

	err = service1.AddChar(secureChar)
	if err != nil {
		log.Fatal(err)
	}

	err = a.Run()
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("Exposed server %s", service1.Properties.UUID)

	timeout := uint32(6 * 3600) // 6h
	log.Infof("Advertising for %ds...", timeout)
	cancel, err := a.Advertise(timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer cancel()

	wait := make(chan bool)
	go func() {
		time.Sleep(time.Duration(timeout) * time.Second)
		wait <- true
	}()

	<-wait
}