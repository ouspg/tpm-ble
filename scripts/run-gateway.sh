#!/bin/sh
set -e

HOST="tpm-pi-server"

alias rpi_scp="scp -i ./keys/ssh/pi_key.priv"
alias rpi_ssh="ssh -t -i ./keys/ssh/pi_key.priv"

echo "Building for RPi..."
CGO_LDFLAGS="-Xlinker -rpath-link=/usr/arm-linux-gnueabihf/lib/ -L/usr/arm-linux-gnueabihf/lib/ -L/usr/lib/arm-linux-gnueabihf/" \
CGO_CFLAGS="-march=armv7-a -fno-stack-protector" CC=arm-linux-gnueabihf-gcc GOARCH=arm \
CGO_ENABLED=1 GOARCH=arm go build -o ./build/gw examples/gateway/main.go

echo "Transferring..."
rpi_scp ./build/gw pi@$HOST:/tmp/gw
rpi_scp ./ca/keys/cacert.pem pi@$HOST:/tmp/cacert.pem
rpi_ssh pi@$HOST 'sudo mv /tmp/cacert.pem /usr/local/share/keys/tpm-cacert.pem'

ssh -t -i ./keys/ssh/pi_key.priv pi@$HOST 'sudo LD_LIBRARY_PATH="/usr/local/lib" /tmp/gw'