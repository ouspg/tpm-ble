package ble

import (
	"github.com/muka/go-bluetooth/bluez/profile/device"
	"github.com/ouspg/tpm-ble/pkg/crypto"
)

type ClientConnection struct {
	isSecure bool
	clientCertificate []byte

	hwAddr string
	dev *device.Device1

	exchangeRes []byte
	oobDataRes []byte

	cipherSession *crypto.CipherSession
}

func (conn *ClientConnection) Close() {

}

func NewClientConnection() *ClientConnection {
	return &ClientConnection{
		isSecure:          false,
		clientCertificate: nil,
		hwAddr:            "",
	}
}

