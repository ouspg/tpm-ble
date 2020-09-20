package main

import (
	"encoding/hex"
	"github.com/muka/go-bluetooth/api/service"
	"github.com/muka/go-bluetooth/bluez/profile/agent"
	"github.com/muka/go-bluetooth/bluez/profile/gatt"
	"github.com/ouspg/tpm-ble/pkg/ble"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"os/signal"
	"strings"
)


const (
	srcAdapterId           = "hci0"
	dstAdapterId           = "hci1"
	targetPeripheralHWAddr = "41:7F:1C:57:67:3F"
	SecureServiceUuid      = "FF01"
)

func main()  {
	log.SetLevel(log.DebugLevel)

	log.Warn("Descriptions, writes and indications not supported currently")

	cert, err := ioutil.ReadFile("/usr/local/share/keys/tpm_cert.pem")
	if err != nil {
		log.Fatalf("Could not read certificate. Reason: %s", err)
	}

	ble.EnableLESingleMode(srcAdapterId)
	ble.EnableLESingleMode(dstAdapterId)

	sourceDev, err := ble.Client(srcAdapterId, targetPeripheralHWAddr, false)
	if err != nil {
		log.Fatal(err)
	}
	defer sourceDev.Close()

	secApp, err := ble.NewSecureApp(service.AppOptions{
		AdapterID:  dstAdapterId,
		AgentCaps:  agent.CapNoInputNoOutput,
		UUIDSuffix:  ble.SEC_APP_UUID_SUFFIX,
		UUID: ble.APP_UUID,
		AgentSetAsDefault: false,
	})
	if err != nil {
		log.Fatal(err)
	}

	defer secApp.App.Close()

	secApp.App.SetName("Insecure <-> Secure gateway")

	// Handles establishing a secure connection
	err = ble.CreateKeyExchangeService( secApp, "/usr/local/share/keys/tpm-cacert.pem",
		cert, "/usr/local/share/keys/tpm_priv.key")
	if err != nil {
		log.Fatal(err)
	}

	secService, err := secApp.App.NewService(SecureServiceUuid)
	if err != nil {
		log.Fatal(err)
	}

	err = secApp.App.AddService(secService)
	if err != nil {
		log.Fatal(err)
	}

	services, err := ble.GetServices(sourceDev)
	if err != nil {
		log.Fatal(err)
	}


	// Add dummy services to inform what services this gateway has secured
	// Actual secured characteristics "belong" the "secService"
	for _, servicePath := range services {
		log.Infof("Service path: %s", servicePath)

		parts := strings.Split(servicePath, ":")
		_, err = secApp.App.NewService(parts[0])
		if err != nil {
			log.Fatal(err)
		}
	}

	chars := ble.GetCharacteristics(sourceDev)
	for _, charPath := range chars {
		char, err := gatt.NewGattCharacteristic1(charPath)
		if err != nil {
			log.Fatal(err)
		}

		charShortUUID := ble.GetCharUUIDFromUUID(char.Properties.UUID)

		log.Infof("Found characteristic: %s, %s\n", strings.ToUpper(char.Properties.UUID),
			ble.GetCharUUIDFromUUID(char.Properties.UUID))
		log.Println("Flags: ", char.Properties.Flags)

		var newFlags []string
		secureChar, err := secService.NewChar(charShortUUID)
		if err != nil {
			log.Fatal(err)
		}

		if ble.CharacteristicSupportsNotify(char) {
			log.Infof("Add notify for char %s\n", charShortUUID)

			newFlags = append(newFlags, gatt.FlagCharacteristicNotify)

			go func() {
				notifyChan, err := ble.StartCharacteristicNotify(sourceDev, char.Properties.UUID)
				if err != nil {
					log.Fatal(err)
				}

				for val := range notifyChan {
					log.Infof("Characteristic %s received notify value: %s\n",
							charShortUUID, hex.EncodeToString(val))
					_ = secApp.SecureWrite(secureChar, val, nil)
				}
			}()
		}

		if ble.CharacteristicIsReadable(char) {
			log.Infof("Add read for char %s\n", charShortUUID)

			newFlags = append(newFlags, gatt.FlagCharacteristicRead)

			secApp.OnReadSecure(secureChar, func(c *service.Char, options map[string]interface{}) ([]byte, error) {
				return char.ReadValue(nil)
			})
		}

		if ble.CharacteristicIsWritable(char) {
			log.Infof("Add write for char %s\n", charShortUUID)

			newFlags = append(newFlags, gatt.FlagCharacteristicWrite)

			secApp.OnWriteSecure(secureChar, func(c *service.Char, value []byte) ([]byte, error) {
				return nil, char.WriteValue(value, nil)
			})
		}

		if len(newFlags) > 0 {
			secureChar.Properties.Flags = newFlags
			err = secService.AddChar(secureChar)
			if err != nil {
				log.Fatal(err)
			}
		}
	}

	err = secApp.App.Run()
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
