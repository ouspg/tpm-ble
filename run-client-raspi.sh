#!/bin/sh
set -e

echo "Building for RPi3..."
CGO_LDFLAGS="-Xlinker -rpath-link=/usr/arm-linux-gnueabihf/lib/ -L/usr/arm-linux-gnueabihf/lib/ -L/usr/lib/arm-linux-gnueabihf/" \
CGO_CFLAGS="-march=armv7-a -fno-stack-protector" CC=arm-linux-gnueabihf-gcc GOARCH=arm \
CGO_ENABLED=1 GOARCH=arm go build -o ./build/raspi_client cmd/tpm-ble-oob-exchange/client.go

echo "Transferring..."
scp -i ./keys/ssh/pi_key.priv ./build/raspi_client pi@192.168.1.11:/tmp/raspi_client

echo "Run"
ssh -t -i ./keys/ssh/pi_key.priv pi@192.168.1.11 'sudo /tmp/raspi_client'