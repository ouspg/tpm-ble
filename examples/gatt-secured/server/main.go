package main

import (
	"github.com/muka/go-bluetooth/api/service"
	"github.com/muka/go-bluetooth/bluez/profile/agent"
	"github.com/muka/go-bluetooth/bluez/profile/gatt"
	"github.com/ouspg/tpm-ble/pkg/ble"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"time"
)

var adapterID = "hci0"

const ServiceUuid = "ABCD"
const CharUuid = "10000001"
const CharUuidNotify = "10000002"

func main()  {
	cert, err := ioutil.ReadFile("/usr/local/share/keys/tpm_cert.pem")
	if err != nil {
		log.Fatalf("Coul not read certificate. Reason: %s", err)
	}

	privKey, err := ioutil.ReadFile("/usr/local/share/keys/tpm_priv.key")
	if err != nil {
		log.Fatalf("Could not read private key. Reason: %s", err)
	}

	ble.EnableLESingleMode(adapterID)

	secApp, err := ble.NewSecureApp(service.AppOptions{
		AdapterID:  adapterID,
		AgentCaps:  agent.CapNoInputNoOutput,
		UUIDSuffix: ble.APP_UUID_SUFFIX,
		UUID: ble.APP_UUID,
	})
	if err != nil {
		log.Fatal(err)
	}

	app := secApp.App
	defer app.Close()

	app.SetName("GATT secured")

	// Handles establishing a secure connection
	err = ble.CreateKeyExchangeService( secApp, "/usr/local/share/keys/tpm-cacert.pem",
		cert, privKey)
	if err != nil {
		log.Fatal(err)
	}

	service1, err := app.NewService(ServiceUuid)
	if err != nil {
		log.Fatal(err)
	}

	err = app.AddService(service1)
	if err != nil {
		log.Fatal(err)
	}

	secureChar, err := service1.NewChar(CharUuid)
	if err != nil {
		log.Fatal(err)
	}

	secureChar.Properties.Flags = []string{
		gatt.FlagCharacteristicRead,
	}

	secApp.OnReadSecure(secureChar, func(c *service.Char, options map[string]interface{}) (bytes []byte, err error) {
		return []byte("This message is secured on gatt level"), nil
	})

	err = service1.AddChar(secureChar)
	if err != nil {
		log.Fatal(err)
	}

	secureCharNotify, err := service1.NewChar(CharUuidNotify)
	if err != nil {
		log.Fatal(err)
	}

	secureCharNotify.Properties.Flags = []string{
		gatt.FlagCharacteristicNotify,
	}

	secApp.OnReadSecure(secureCharNotify, func(c *service.Char, options map[string]interface{}) (bytes []byte, err error) {
		return []byte("This message is secured on gatt level"), nil
	})

	err = service1.AddChar(secureCharNotify)
	if err != nil {
		log.Fatal(err)
	}

	err = app.Run()
	if err != nil {
		log.Fatal(err)
	}

	err = secApp.Advertise(ble.AdvertiseForever)
	if err != nil {
		log.Fatal(err)
	}

	ticker := time.NewTicker(5 * time.Second)

	go func() {
		for {
			<-ticker.C
			log.Println("Write secure notify")
			_ = secApp.SecureWrite(secureCharNotify, []byte("test"), nil)
		}
	}()

	// Run until interrupt
	wait := make(chan os.Signal, 1)
	signal.Notify(wait, os.Interrupt)
	<-wait
}