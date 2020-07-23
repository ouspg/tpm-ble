package main

import (
	"encoding/hex"
	"github.com/ouspg/tpm-ble/pkg/ble"
	"github.com/ouspg/tpm-ble/pkg/btmgmt"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
)

const TargetHwaddr = "DC:A6:32:35:EF:E2"

const MySecureBleHwaddr = "DC:A6:32:28:34:E4"

func main()  {
	/*err := crypto.InitializeTPMEngine()
	if err != nil {
		log.Fatalf("Could not initialize TPM engine: %s", err)
	}*/

	cert, err := ioutil.ReadFile("/usr/local/share/keys/tpm_cert.pem")
	if err != nil {
		log.Fatalf("Could not read certificate. Reason: %s", err)
	}

	secDev, err := ble.CreateSecureConnection("/usr/local/share/ca-certificates/tpm-cacert.pem", cert,
		"/usr/local/share/keys/tpm_priv.key", "hci0", TargetHwaddr)
	if err != nil {
		log.Fatalf("Could not connect to BLE remote: %s", err)
	}

	bleDev := secDev.Dev

	defer bleDev.Disconnect() // Disconnect when the program exists
	defer bleDev.Close()

	oobData, err := ble.ExchangeOOBData(bleDev, secDev.CipherSession, MySecureBleHwaddr)
	if err != nil {
		log.Fatalf("Could not exchange tokens: %s", err)
	}

	log.Printf("Received oob data: %s", hex.EncodeToString(oobData.Data[:]))

	oobHash := oobData.Data[:16]
	oobRandomizer := oobData.Data[16:]

	err = btmgmt.AddRemoteOOBData(0, oobData.Address, btmgmt.LE_PUBLIC,
		nil, nil, oobHash, oobRandomizer)
	if err != nil {
		log.Fatalf("Could not add remote oob data for address: %s. Reason: %s\n", oobData.Address, err)
	}
	log.Infof("Added remote oob data for address: %s\n", oobData.Address)
}
