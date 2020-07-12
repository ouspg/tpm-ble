package ble

import (
	"encoding/json"
)

const UUID_SUFFIX = "-0000-1000-8000-00805F9B34FB"
const APP_UUID = "0001"
const SERVICE_UUID = "0001"

const READ_CERT_1_CHAR_UUID = "00000002" // ECDSA
const READ_CERT_2_CHAR_UUID = "00000003" // ECDSA
const READ_CERT_3_CHAR_UUID = "00000004" // ECDSA

const ECDH_EXC_CHAR_UUID = "00000010" // ECDH
const OOB_EXC_CHAR_UUID = "00000020"  // OOB token exchange


const TRUSTED_CA = "/usr/local/share/ca-certificates/tpm-cacert.pem"

type ECDHExchange struct {
	Signature []byte `json:"sig"`
	PubKey []byte `json:"pub"`
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

func EnableForceSecureBLEPairing() {



}