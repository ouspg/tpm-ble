#!/bin/bash
set -e
shopt -s expand_aliases

HOST=$1 # Remote host, where TPM is attached

echo "HOST: $HOST"

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
alias ssh_rpi="ssh -t -i ./keys/ssh/pi_key.priv pi@$HOST"

if [ "${NO_TPM,,}" = "true" ]; then
  echo "Generate non-protected key"
  ssh_rpi 'sudo mkdir -p '$KEYDIR \
      '&& sudo openssl ecparam -name prime256v1 -genkey -noout -out '$KEYPATH'_priv.key && echo "Priv key created"' \
      '&& sudo openssl ec -in '${PRIVKEY_PATH}' -pubout -outform pem -out '${PUBKEY_PATH} \
      '&& echo "Pub key created"' \
      '&& sudo openssl req -new -key '${PRIVKEY_PATH}' -out '$CSRPATH' -nodes -subj "'${CSRSUBJ}'" -outform PEM' \
      '&& echo "Certificate signing request created"'
else
  echo "Generate protected key"
  ssh_rpi 'sudo mkdir -p '$KEYDIR \
    '&& sudo tpm2tss-genkey -a ecdsa -c nist_p256 '$KEYPATH'_priv.key && echo "Priv key created"' \
    '&& sudo openssl ec -engine tpm2tss -inform engine -in '${PRIVKEY_PATH}' -pubout -outform pem -out '${PUBKEY_PATH} \
    '&& echo "Pub key created"' \
    '&& sudo openssl req -new -engine tpm2tss -keyform engine -key '${PRIVKEY_PATH}' -out '$CSRPATH' -nodes -subj "'${CSRSUBJ}'" -outform PEM' \
    '&& echo "Certificate signing request created"'
fi

echo "Copy CSR from remote to local CA dir"

scp_rpi pi@$HOST:$CSRPATH ./ca/

cd ca
/usr/local/ssl/bin/openssl ca -config ./openssl-ca.cnf -policy signing_policy -extensions signing_req -out ./$PEMNAME -infiles ./$CSRNAME
X509_CERT=$(/usr/local/ssl/bin/openssl x509 -in ./$PEMNAME)
echo ${X509_CERT}
rm ./$CSRNAME
cd ..

echo "Certificate created, copy to remote"

ssh_rpi "echo '${X509_CERT}' > $KEYDIR/$PEMNAME"

rm ./ca/$PEMNAME

