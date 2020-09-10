package main

import (
	"encoding/hex"
	"github.com/muka/go-bluetooth/bluez/profile/gatt"
	"github.com/ouspg/tpm-ble/pkg/ble"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
)

var adapterID = "hci0"

const TargetHwaddr = "00:1A:7D:DA:71:07"

const CharUuid = "10000001"

// https://www.bluetooth.com/specifications/gatt/characteristics/
// org.bluetooth.characteristic.heart_rate_measurement
const HeartRateMeasurementCharUuid = "00002A37"

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

	chars := ble.GetCharacteristics(bleDev)
	for _, charPath := range chars {
		char, err := gatt.NewGattCharacteristic1(charPath)
		if err != nil {
			log.Fatal(err)
		}

		// charShortUUID := ble.GetCharUUIDFromUUID(char.Properties.UUID)
		log.Println("Found char UUID: ", char.Properties.UUID)
	}

	data, err := secDev.SecureReadCharacteristic(HeartRateMeasurementCharUuid + ble.SEC_APP_UUID_SUFFIX)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Read secured characteristic value: %s", data)

	notifyCh, err := secDev.StartSecureCharacteristicNotify(HeartRateMeasurementCharUuid + ble.SEC_APP_UUID_SUFFIX)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		for {
			notifyVal, more := <- notifyCh
			log.Printf("Received notify value: %s\n", hex.EncodeToString(notifyVal))

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