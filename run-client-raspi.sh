#!/bin/sh

echo "Building..."
GOARCH=arm go build -o ./build/raspi_client cmd/tpm-ble-oob-exchange/client.go

echo "Transferring..."
scp -i ./keys/ssh/pi_key.priv ./build/raspi_client pi@192.168.1.11:/tmp/raspi_client

echo "Run"
ssh -t -i ./keys/ssh/pi_key.priv pi@192.168.1.11 'sudo /tmp/raspi_client -v'