package main

import (
	"github.com/ouspg/tpm-ble/pkg/ble"
	"io/ioutil"
	"log"
)

var adapterID = "hci0"

const TargetHwaddr = "DC:A6:32:35:EF:E2"

const CharUuid = "10000001"

func main()  {
	/*err := crypto.InitializeTPMEngine()
	if err != nil {
		log.Fatalf("Could not initialize TPM engine: %s", err)
	}*/

	cert, err := ioutil.ReadFile("/usr/local/share/keys/tpm_cert.pem")
	if err != nil {
		log.Fatalf("Could not read certificate. Reason: %s", err)
	}

	ble.EnableLESingleMode(adapterID)

	secDev, err := ble.CreateSecureConnection("/usr/local/share/ca-certificates/tpm-cacert.pem", cert,
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
}