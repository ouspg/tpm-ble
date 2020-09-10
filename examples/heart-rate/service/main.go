package main

import (
	"encoding/binary"
	"github.com/muka/go-bluetooth/api/service"
	"github.com/muka/go-bluetooth/bluez/profile/agent"
	"github.com/muka/go-bluetooth/bluez/profile/gatt"
	"github.com/ouspg/tpm-ble/pkg/ble"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"os/signal"
	"time"
)

var adapterID = "hci0"

const UuidSuffix = "-0000-1000-8000-00905F9B34FB"
const AppUuid = "0001"

// Heart rate service specification: https://www.bluetooth.org/docman/handlers/downloaddoc.ashx?doc_id=308344
// http://www.mariam.qa/post/hr-ble/

// https://www.bluetooth.com/specifications/gatt/services/
// org.bluetooth.service.heart_rate
const HeartRateServiceUuid = "180D"

// https://www.bluetooth.com/specifications/gatt/characteristics/
// org.bluetooth.characteristic.heart_rate_measurement
const HeartRateMeasurementCharUuid = "2A37"

func main()  {
	cert, err := ioutil.ReadFile("/usr/local/share/keys/tpm_cert.pem")
	if err != nil {
		log.Fatalf("Coul not read certificate. Reason: %s", err)
	}

	ble.EnableLESingleMode(adapterID)

	secApp, err := ble.NewSecureApp(service.AppOptions{
		AdapterID:  adapterID,
		AgentCaps:  agent.CapNoInputNoOutput,
		UUIDSuffix: UuidSuffix,
		UUID:       AppUuid,
	})
	if err != nil {
		log.Fatal(err)
	}

	app := secApp.App
	defer app.Close()

	app.SetName("Secure heart rate sensor")

	// Handles establishing a secure connection
	err = ble.CreateKeyExchangeService( secApp, "/usr/local/share/keys/tpm-cacert.pem",
		cert, "/usr/local/share/keys/tpm_priv.key")
	if err != nil {
		log.Fatal(err)
	}

	service1, err := app.NewService(HeartRateServiceUuid)
	if err != nil {
		log.Fatal(err)
	}

	err = app.AddService(service1)
	if err != nil {
		log.Fatal(err)
	}


	secureCharNotify, err := service1.NewChar(HeartRateMeasurementCharUuid)
	if err != nil {
		log.Fatal(err)
	}

	secureCharNotify.Properties.Flags = []string{
		gatt.FlagCharacteristicNotify,
	}

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
			measurement := make([]byte, 23)

			flag := byte(1 << 7) // 0 if UINT8 values, 1 if UINT16
			flag |= 1 << 3 // 1 if RR-interval measurements are present
			measurement[0] = flag

			// HR value
			binary.LittleEndian.PutUint16(measurement[2:], 100)
			_ = secApp.SecureWrite(secureCharNotify, measurement, nil)

			log.Info("Publish measurement")
		}
	}()

	// Run until interrupt
	wait := make(chan os.Signal, 1)
	signal.Notify(wait, os.Interrupt)
	<-wait
}