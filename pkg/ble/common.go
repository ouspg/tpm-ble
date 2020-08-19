package ble

import (
	"crypto/rand"
	"encoding/json"
	"github.com/muka/go-bluetooth/hw"
	"log"
)

const APP_UUID_SUFFIX = "-0000-1000-8000-00805F9B34FB"
const APP_UUID = "0001"

const KEY_EXC_SERVICE_UUID = "0001"
const OOB_EXC_SERVICE_UUID = "0002"

const READ_CERT_1_CHAR_UUID = "00000002" // ECDSA
const READ_CERT_2_CHAR_UUID = "00000003" // ECDSA
const READ_CERT_3_CHAR_UUID = "00000004" // ECDSA

const WRITE_CERT_CHAR_UUID = "00000005" // ECDSA

const ECDH_EXC_CHAR_UUID = "00000010" // ECDH
const OOB_EXC_CHAR_UUID = "00000020"  // OOB token exchange


type ECDHExchange struct {
	Signature []byte `json:"sig"`
	PubKey []byte `json:"pub"`
	Random [32]byte `json:"r"`
}

// Allow specifying MAC in case pairing is done for another adapter
type OOBExchange struct {
	Data [32]byte `json:"data"` // OOB data (hash, randomizer)
	Address string `json:"addr"` // MAC address of the device this oob data should be added to
}

func MarshalECDHExchange(exchange ECDHExchange) ([]byte, error) {
	return json.Marshal(exchange)
}

func UnmarshalECDHExchange(data []byte) (*ECDHExchange, error) {
	var exchange ECDHExchange
	err := json.Unmarshal(data, &exchange)
	if err != nil {
		return nil, err
	}
	return &exchange, nil
}

func MarshalOOBExchange(exchange OOBExchange) ([]byte, error) {
	return json.Marshal(exchange)
}

func UnmarshalOOBExchange(data []byte) (*OOBExchange, error) {
	var exchange OOBExchange
	err := json.Unmarshal(data, &exchange)
	if err != nil {
		return nil, err
	}
	return &exchange, nil
}

func EnableLESingleMode(adapterID string) {
	btmgmtCli := hw.NewBtMgmt(adapterID)
	btmgmtCli.SetPowered(false)

	btmgmtCli.SetLe(true)
	btmgmtCli.SetBredr(false)

	btmgmtCli.SetPowered(true)
}

func SecRand32Bytes() (out [32]byte) {
	bytes := make([]byte, 32)

	n, err := rand.Read(bytes)
	if n != 32 || err != nil {
		log.Fatalf("Could not generate secure random bytes. Count :%d, err: %v\n", n, err)
	}

	copy(out[:], bytes)
	return
}