#!/bin/sh
set -e

HOST="tpm-pi-client"

alias rpi_scp="scp -i ./keys/ssh/pi_key.priv"
alias rpi_ssh="ssh -t -i ./keys/ssh/pi_key.priv"

echo "Building for RPi..."
CGO_LDFLAGS="-Xlinker -rpath-link=/usr/arm-linux-gnueabihf/lib/ -L/usr/arm-linux-gnueabihf/lib/ -L/usr/lib/arm-linux-gnueabihf/" \
CGO_CFLAGS="-march=armv7-a -fno-stack-protector" CC=arm-linux-gnueabihf-gcc GOARCH=arm \
CGO_ENABLED=1 GOARCH=arm go build -o ./build/raspi_client cmd/ble-oob-exchange/client.go

echo "Transferring..."
rpi_scp ./build/raspi_client pi@$HOST:/tmp/raspi_client
rpi_scp ./ca/keys/cacert.pem pi@$HOST:/tmp/cacert.pem
rpi_ssh pi@$HOST 'sudo mv /tmp/cacert.pem /usr/local/share/ca-certificates/tpm-cacert.pem'

rpi_ssh pi@$HOST 'sudo /tmp/raspi_client'
