#!/bin/bash
set -e
shopt -s expand_aliases

KERNEL="kernel7l"

alias scp_rpi="scp -i ./keys/ssh/pi_key.priv"
alias ssh_rpi="ssh -t -i ./keys/ssh/pi_key.priv pi@$HOST"

ssh_rpi 'rm -rf /tmp/kernel_deploy && mkdir -p /tmp/kernel_deploy && mkdir -p /tmp/kernel_deploy/boot'


rsync -e "ssh -i ./keys/ssh/pi_key.priv" -avz /home/tpm/raspi/install_modules/ pi@$HOST:/tmp/kernel_deploy/
rsync -e "ssh -i ./keys/ssh/pi_key.priv" -avz /home/tpm/raspi/linux/arch/arm/boot/dts/*.dtb pi@$HOST:/tmp/kernel_deploy/boot/
rsync -e "ssh -i ./keys/ssh/pi_key.priv" -avz /home/tpm/raspi/linux/arch/arm/boot/dts/overlays/*.dtb* pi@$HOST:/tmp/kernel_deploy/boot/overlays/
rsync -e "ssh -i ./keys/ssh/pi_key.priv" -avz /home/tpm/raspi/linux/arch/arm/boot/zImage pi@$HOST:/tmp/kernel_deploy/boot/$KERNEL.img

ssh_rpi 'sudo cp -r /tmp/kernel_deploy/boot/*.dtb /boot/'
ssh_rpi 'sudo cp -r /tmp/kernel_deploy/boot/'$KERNEL'.img /boot/'
ssh_rpi 'sudo cp -r /tmp/kernel_deploy/boot/overlays/*.dtb* /boot/overlays/'
ssh_rpi 'sudo cp -r /tmp/kernel_deploy/lib/modules/* /lib/modules/'
ssh_rpi 'sudo reboot'