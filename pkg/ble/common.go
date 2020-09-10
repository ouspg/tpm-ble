package ble

import (
	"crypto/rand"
	"encoding/json"
	"github.com/muka/go-bluetooth/hw"
	"log"
	"strings"
)

const SEC_APP_UUID_SUFFIX = "-0000-1000-8000-00805F9B34FB"
const APP_UUID = "0001"

const KEY_EXC_SERVICE_UUID = "0001"
const OOB_EXC_SERVICE_UUID = "0002"

const READ_CERT_1_CHAR_UUID = "00000002" // ECDSA
const READ_CERT_2_CHAR_UUID = "00000003" // ECDSA
const READ_CERT_3_CHAR_UUID = "00000004" // ECDSA

const WRITE_CERT_CHAR_UUID = "00000005" // ECDSA

const ECDH_EXC_CHAR_UUID = "00000010" // ECDH
const OOB_EXC_CHAR_UUID = "00000020"  // OOB token exchange
const CHALLENGE_CHAR_UUID = "00000030" // ChallengeResponse

type ECDHExchange struct {
	Signature []byte `json:"s"`
	PubKey []byte `json:"p"`
	Random [32]byte `json:"r"` // challenge
}

/**
Challenge the other party to sign the random value that is send in the ECDHExchange message
This mitigates a scenario where the adversary has access to the ECDH private key and has sniffed the ECDHExchange
message that contains the signature of the ECDH key (signed using ECDSA). Without this mitigation, the adversary could establish a session by
by replaying the ECDHExchange message that contains the signature of the public ECDH key, whose private key the has adversary stolen.
This attack would bypass the TPM (ECDSA).
 */
type ChallengeResponse struct {
	Signature []byte `json:"s"`
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

func MarshalChallengeResponse(response ChallengeResponse) ([]byte, error) {
	return json.Marshal(response)
}

func UnmarshalChallengeResponse(data []byte) (*ChallengeResponse, error) {
	var response ChallengeResponse
	err := json.Unmarshal(data, &response)
	if err != nil {
		return nil, err
	}
	return &response, nil
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

// Extract characteristic UUID from full UUID (e.g., 00002A38-0000-1000-8000-00805F9B34FB)
// and pad to full length (8 characters)
// Returns empty string if invalid uuid
func GetCharUUIDFromUUID(uuid string) string {
	parts := strings.Split(uuid, "-")
	if len(parts) == 0 {
		return ""
	}

	padLen := 8 - len(parts[0])
	return strings.ToUpper(strings.Repeat("0", padLen) + parts[0])
}