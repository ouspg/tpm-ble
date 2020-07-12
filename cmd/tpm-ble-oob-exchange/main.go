package main

import (
	"github.com/ouspg/tpm-bluetooth/pkg/ble"
	"io/ioutil"
	"log"
)

func main() {
	// x509
	cert, err := ioutil.ReadFile("/usr/local/share/keys/tpm_cert.pem")
	if err != nil {
		log.Fatalf("Coul not read certificate. Reason: %s", err)
	}

	privKey, err := ioutil.ReadFile("/usr/local/share/keys/tpm_priv.key")
	if err != nil {
		log.Fatalf("Coul not read private key. Reason: %s", err)
	}

	err = ble.CreateKeyExchangeService("hci0", cert, privKey)
	if err != nil {
		log.Fatal(err)
	}
}
