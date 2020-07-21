#!/bin/sh
cd ca
/usr/local/ssl/bin/openssl req -x509 -config openssl-ca.cnf -newkey rsa:4096 -sha256 -nodes -out keys/cacert.pem -outform PEM
mv cakey.pem ./keys
cd ..