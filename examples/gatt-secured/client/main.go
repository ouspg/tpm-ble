package main

import (
	"github.com/ouspg/tpm-ble/pkg/ble"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
)

var adapterID = "hci0"

const TargetHwaddr = "DC:A6:32:28:34:E4"

const CharUuid = "10000001"
const CharNotifyUuid = "10000002"

func main()  {
	cert, err := ioutil.ReadFile("/usr/local/share/keys/tpm_cert.pem")
	if err != nil {
		log.Fatalf("Could not read certificate. Reason: %s", err)
	}

	ble.EnableLESingleMode(adapterID)

	secDev, err := ble.CreateSecureConnection("/usr/local/share/keys/tpm-cacert.pem", cert,
		"/usr/local/share/keys/tpm_priv.key", "hci0", TargetHwaddr)
	if err != nil {
		log.Fatalf("Could not connect to BLE remote: %s", err)
	}

	bleDev := secDev.Dev

	defer bleDev.Disconnect() // Disconnect when program exists
	defer bleDev.Close()

	data, err := secDev.SecureReadCharacteristic(CharUuid + ble.APP_UUID_SUFFIX)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Read secured characteristic value: %s", data)

	notifyCh, err := secDev.StartSecureCharacteristicNotify(CharNotifyUuid + ble.APP_UUID_SUFFIX)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		for {
			notifyVal, more := <- notifyCh
			log.Printf("Received notify value: %s\n", notifyVal)

			if !more {
				log.Print("Notify channel was closed")
				return
			}
		}
	}()

	// Run until interrupt
	wait := make(chan os.Signal, 1)
	signal.Notify(wait, os.Interrupt)
	<-wait
}