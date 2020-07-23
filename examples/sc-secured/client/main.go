package main

import (
	"github.com/ouspg/tpm-ble/pkg/ble"
	"log"
	"time"
)

const TARGET_HWADDR = "DC:A6:32:35:EF:E2"
const UUID_SUFFIX = "-0000-1000-8000-00805F9B34FB"
const APP_UUID = "0001"
const SERVICE_UUID = "0001"

const SECURE_CHAR_UUID = "00000001"

func main()  {
	dev, err := ble.CreateConnection("hci0", TARGET_HWADDR)
	if err != nil {
		log.Fatalf("Could not connect to BLE remote: %s", err)
	}

	/*iprops, err := dev.GetProperties()
	if err != nil {
		log.Fatal(err)
	}

	f !props.Paired || !props.Trusted {
		log.Println("Pair")

		err := dev.Pair()
		if err != nil {
			log.Fatalf("Pair failed: %s", err)
		}

		err = agent.SetTrusted("hci0", dev.Path())
		if err != nil {
			log.Fatal(err)
		}
	}*/


	for true {
		res, err := ble.ReadCharacteristic(dev, SECURE_CHAR_UUID + UUID_SUFFIX)
		if err != nil {
			log.Fatalf("Could not read characteristic: %s", err)
		}

		log.Printf("Result: %s\n", string(res))
		time.Sleep(1 * time.Second)
	}


}
