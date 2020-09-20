package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/muka/go-bluetooth/bluez/profile/gatt"
	"github.com/ouspg/tpm-ble/pkg/ble"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
)

var adapterID = "hci0"

const TargetHwaddr = "DC:A6:32:28:34:E4"

// https://www.bluetooth.com/specifications/gatt/characteristics/
// org.bluetooth.characteristic.heart_rate_measurement
const HeartRateMeasurementCharUuid = "00002A37"

type HRMeasurement struct {
	value uint16 // heart rate measurement
	scSupport uint8 // sensor contact
	ee bool // Energy Expended
	rr []float32 // rr-intervals in seconds
}

func unmarshalHRMeasurement(raw []byte, measurement* HRMeasurement) error {
	if len(raw) < 2 {
		return fmt.Errorf("Measurement is too short. Length: %d: ", len(raw))
	}

	measurement.value = 0
	measurement.rr = []float32{}

	flag := raw[0]

	is16Bit := ((flag >> 7) & 1) == 1
	measurement.scSupport = (flag >> 5) & 3
	measurement.ee = ((flag >> 4) & 1) == 1
	hasRR := ((flag >> 3) & 1) == 1

	log.Printf("Flags: is 16bit: %t, has EE: %t, has RR-intervals: %t\n", is16Bit, measurement.ee, hasRR)

	if is16Bit {
		measurement.value = binary.LittleEndian.Uint16(raw[1:2])
	} else {
		measurement.value = uint16(raw[1])
	}

	if !hasRR {
		return nil
	}

	nRRIdx := 2

	if is16Bit {
		nRRIdx += 1
	}

	if measurement.ee {
		nRRIdx += 1
	}

	for i := nRRIdx; i < len(raw) - 1; i += 2 {
		measurement.rr = append(measurement.rr, float32(binary.LittleEndian.Uint16(raw[i:i+2])) / 1024)
	}
	return nil
}

func main()  {
	logrus.SetLevel(logrus.DebugLevel)

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
		logrus.Warn(err)
	}

	log.Printf("Read secured characteristic value: %s", data)

	notifyCh, err := secDev.StartSecureCharacteristicNotify(HeartRateMeasurementCharUuid + ble.SEC_APP_UUID_SUFFIX)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		for {
			rawMeasurement, more := <- notifyCh
			log.Printf("Received raw measurement value: %s\n", hex.EncodeToString(rawMeasurement))

			var measurement HRMeasurement
			err := unmarshalHRMeasurement(rawMeasurement, &measurement)
			if err != nil {
				log.Print(err)
			}

			log.Printf("Heart rate: %d\n", measurement.value)
			if len(measurement.rr) > 0 {
				log.Printf("RR-intervals (in seconds): %v\n", measurement.rr)
			}

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