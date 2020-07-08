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


const TRUSTED_CA = `
-----BEGIN CERTIFICATE-----
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
QJbgEsc30iUHTA==
-----END CERTIFICATE-----
`


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