package main

import (
	"encoding/hex"
	"github.com/muka/go-bluetooth/bluez/profile/gatt"
	"github.com/ouspg/tpm-ble/pkg/ble"
	log "github.com/sirupsen/logrus"
	"os"
	"os/signal"
	"strings"
)

var adapterID = "hci0"


/**
dict entry(
         string "org.bluez.GattCharacteristic1"
         array [
            dict entry(
               string "UUID"
               variant                   string "98ed0003-a541-11e4-b6a0-0002a5d5c51b"
            )
            dict entry(
               string "Service"
               variant                   object path "/org/bluez/hci0/dev_A0_38_F8_F0_DF_68/service0010"
            )
            dict entry(
               string "Value"
               variant                   array [
                  ]
            )
            dict entry(
               string "Notifying"
               variant                   boolean false
            )
            dict entry(
               string "Flags"
               variant                   array [
                     string "read"
                     string "notify"
                  ]
            )
            dict entry(
               string "NotifyAcquired"
               variant                   boolean false
            )
         ]
      )

dict entry(
               string "UUID"
               variant                   string "00060001-f8ce-11e4-abf4-0002a5d5c51b"
            )
            dict entry(
               string "Service"
               variant                   object path "/org/bluez/hci0/dev_A0_38_F8_F0_DF_68/service0016"
            )
            dict entry(
               string "Value"
               variant                   array [
                  ]
            )
            dict entry(
               string "Notifying"
               variant                   boolean false
            )
            dict entry(
               string "Flags"
               variant                   array [
                     string "write-without-response"
                     string "write"
                     string "notify"
                  ]
            )
            dict entry(
               string "WriteAcquired"
               variant                   boolean false
            )
            dict entry(
               string "NotifyAcquired"
               variant                   boolean false
            )
 */


func main()  {
	ble.EnableLESingleMode(adapterID)

	dev, err := ble.Client(adapterID, "A0:38:F8:F0:DF:68", true)
	if err != nil {
		log.Fatal(err)
	}

	chars := ble.GetCharacteristics(dev)

	for _, charPath := range chars {
		char, err := gatt.NewGattCharacteristic1(charPath)
		if err != nil {
			log.Fatal(err)
		}

		log.Info("Found characteristic: ", strings.ToUpper(char.Properties.UUID))
		log.Println("Flags: ", char.Properties.Flags)

		if ble.CharacteristicIsReadable(char) {
			val, err := char.ReadValue(nil)
			if err != nil {
				log.Fatal(err)
			}

			log.Info("Read value: ", hex.Dump(val))
		}
	}

	/**
	98ed0002-a541-11e4-b6a0-0002a5d5c51b - write only
	 */

	notifyCh, err := ble.StartCharacteristicNotify(dev, "98ED0003-A541-11E4-B6A0-0002A5D5C51B")
	if err != nil {
		log.Fatal("Start notify failed: ", err)
	}

	go func() {
		for {
			notifyVal, more := <- notifyCh
			log.Printf("Received notify value:\n%s\n", hex.Dump(notifyVal))

			if !more {
				log.Print("Notify channel was closed")
				return
			}
		}
	}()

	log.Info("Notify started")

	// data := []byte{0x01, 0x00}


	// 2 byte header:
	// 1st byte - msg id
	// 2nd byte - msg len (without header)

	// data := []byte{0x16, 0x01, 0x01}
	data := []byte{0x18, 0x03, 0x14, 0x00, 0x10}

	err = ble.WriteCharacteristic(dev, "98ED0002-A541-11E4-B6A0-0002A5D5C51B", data)
	if err != nil {
		log.Fatal("Write failed: ", err)
	}

	// Run until interrupt
	wait := make(chan os.Signal, 1)
	signal.Notify(wait, os.Interrupt)
	<-wait
}
