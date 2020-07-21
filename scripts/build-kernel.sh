#!/bin/sh

set -e

export KERNEL=kernel7l

cd ~/raspi/linux
make -j4 ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- zImage modules dtbs
rm -rf /home/tpm/raspi/install_modules && make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- INSTALL_MOD_PATH=/home/tpm/raspi/install_modules modules_install

