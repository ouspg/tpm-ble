#!/bin/sh
set -e

IP_ADDR="192.168.1.11" # Remote IP, where TPM is attached

KEYDIR="/usr/local/share/keys"
KEYNAME="tpm"
KEYPATH=$KEYDIR'/'$KEYNAME

PRIVKEY_PATH="${KEYPATH}_priv.key"
PUBKEY_PATH="${KEYPATH}_pub.key"

CSRNAME="${KEYNAME}_req.csr"
CSRPATH="$KEYDIR/$CSRNAME"
CSRSUBJ="/CN=test/"

PEMNAME="${KEYNAME}_cert.pem"

alias scp_rpi="scp -i ./keys/ssh/pi_key.priv"
alias ssh_rpi="ssh -t -i ./keys/ssh/pi_key.priv pi@$IP_ADDR"

ssh_rpi 'sudo mkdir -p '$KEYDIR \
  '&& sudo tpm2tss-genkey -a ecdsa -c nist_p256 '$KEYPATH'_priv.key && echo "Priv key created"' \
  '&& sudo openssl ec -engine tpm2tss -inform engine -in '${PRIVKEY_PATH}' -pubout -outform pem -out '${PUBKEY_PATH} \
  '&& echo "Pub key created"' \
  '&& sudo openssl req -new -engine tpm2tss -keyform engine -key '${PRIVKEY_PATH}' -out '$CSRPATH' -nodes -subj "'${CSRSUBJ}'" -outform PEM' \
  '&& echo "Certificate signing request created"'

echo "Copy CSR from remote to local CA dir"

scp_rpi pi@$IP_ADDR:$CSRPATH ./ca/

cd ca
/usr/local/ssl/bin/openssl ca -config ./openssl-ca.cnf -policy signing_policy -extensions signing_req -out ./$PEMNAME -infiles ./$CSRNAME
rm ./$CSRNAME
cd ..

echo "Certificate created, copy to remote"

scp_rpi ./ca/$PEMNAME pi@$IP_ADDR:"/tmp/$PEMNAME"
ssh_rpi sudo mv /tmp/$PEMNAME "$KEYDIR/"

rm ./ca/$PEMNAME

