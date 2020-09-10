package main

import (
	"github.com/ouspg/tpm-ble/pkg/ble"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
)

var adapterID = "hci0"

func main() {
	// x509
	cert, err := ioutil.ReadFile("/usr/local/share/keys/tpm_cert.pem")
	if err != nil {
		log.Fatalf("Coul not read certificate. Reason: %s", err)
	}

	ble.EnableLESingleMode(adapterID)

	secApp, err := ble.CreateOOBDataExchangeApp(0, adapterID,
		"/usr/local/share/ca-certificates/tpm-cacert.pem", cert,
		"/usr/local/share/keys/tpm_priv.key", nil)
	if err != nil {
		log.Fatal(err)
	}

	app := secApp.App
	defer app.Close()

	err = app.Run()
	if err != nil {
		log.Fatal(err)
	}

	err = secApp.Advertise(ble.AdvertiseForever)
	if err != nil {
		log.Fatal(err)
	}

	// Run until interrupt
	wait := make(chan os.Signal, 1)
	signal.Notify(wait, os.Interrupt)
	<-wait
}
