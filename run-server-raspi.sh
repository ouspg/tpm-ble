#!/bin/sh

IP_ADDR="192.168.1.4"

echo "Building for RPi..."
CGO_LDFLAGS="-Xlinker -rpath-link=/usr/arm-linux-gnueabihf/lib/ -L/usr/arm-linux-gnueabihf/lib/ -L/usr/lib/arm-linux-gnueabihf/" \
CGO_CFLAGS="-march=armv7-a -fno-stack-protector" CC=arm-linux-gnueabihf-gcc GOARCH=arm \
CGO_ENABLED=1 GOARCH=arm go build -o ./build/raspi_server cmd/tpm-ble-oob-exchange/main.go

echo "Transferring..."
scp -i ./keys/ssh/pi_key.priv ./build/raspi_server pi@$IP_ADDR:/tmp/raspi_server

echo "Run"
ssh -t -i ./keys/ssh/pi_key.priv pi@$IP_ADDR 'sudo /tmp/raspi_server'