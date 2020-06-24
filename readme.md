
Build raspi kernel with tpm2 support enabled (check gdrive for guide)


Install tpm2-tools:

<https://github.com/tpm2-software/tpm2-tools/wiki/Getting-Started>

<https://github.com/tpm2-software/tpm2-tools/wiki/Creating-Objects>

<https://github.com/tpm2-software/tpm2-tss-engine>

Test keys are located in keys/.

## Start TPM simulator

Start simulator:

```s
~/ibmtpm974/src/tpm_server &
```

In new window, start resource manager (should be configured to run without root in prod system):

```s
sudo tpm2-abrmd --allow-root --tcti=mssim
```

## PKCS#11 (not used)

<https://github.com/tpm2-software/tpm2-pkcs11/blob/master/docs/INITIALIZING.md>

<https://github.com/tpm2-software/tpm2-pkcs11/blob/master/docs/OPENSSL.md>

<https://libraries.io/github/tpm2-software/tpm2-tss-engine>

## Create CA

Create certificate authority. CA files should be stored in a secure environment.
Using CA isn't really necessary, could be configured to trust specific certificate instead.

```s
openssl req -x509 -config openssl-ca.cnf -newkey rsa:4096 -sha256 -nodes -out cacert.pem -outform PEM
```

## TPM generate (pub, priv)

Create primary key under the TPM owner hierarchy

```s
tpm2_createprimary -c primary.ctx
```

```s
tpm2tss-genkey -a ecdsa -c nist_p256 keys/test_priv.key
```

Private key stored on the computer is a wrapped key,
only the TPM can use it.

Generate private key that is not protected by the TPM (for testing without TPM):

```s
openssl ecparam -name prime256v1 -genkey -noout -out test_priv_no_tpm.pem
```

Export pub key:

```s
openssl ec -engine tpm2tss -inform engine -in keys/test_priv.key -pubout -outform pem -out keys/test_pub.pub
```

```s
openssl req new -subj '/CN=my key/' -sha256 -engine tpm2tss -inform engine -in keys/test_priv.key -pubout -outform pem -out keys/test_pub.pub
```

```s
openssl req -config openssl-server.cnf -newkey rsa:2048 -sha256 -nodes -out servercert.csr -outform PEM
```

Test signing data:

```s
openssl dgst -sha256 -engine tpm2tss -keyform engine -sign keys/test_priv.key -out test.sha256 test.txt
```

## Create CSR (certificate signing request)

Create CSR:

```s
openssl req -new -engine tpm2tss -keyform engine -key keys/test_priv.key -out req.csr -nodes -subj '/CN=test/' -outform PEM
```

Create signed certificate:

```s
openssl ca -config openssl-ca.cnf -policy signing_policy -extensions signing_req -out cert.pem -infiles req.csr
```

## Verify certificate

Confirm that the certificate was signed by the CA:

```s
openssl verify -CAfile keys/cacert.pem cert.pem
```

## Bluetooth

See <https://github.com/muka/go-bluetooth> for configuring dbus

bluetooth management API docs: <https://git.kernel.org/pub/scm/bluetooth/bluez.git/tree/doc/mgmt-api.txt>

<https://lists.zephyrproject.org/g/devel/topic/29197639>

Monitor bluetooth:

```s
sudo btmon
```

Secure connections only (4.2):
```s
sc only
```

secure simple pairing (4.0):
```s
ssp on
```

Get random and confirmation value:
```s
le-oob
```

Type 2: LE random, Type 0: BR/EDR,
Use P256

```s
remote-oob -t 0 -R bd12b8a8afc2b00da1c004d584c7a2a5 -H 4772e65de17605fdaf173b089fd56c25 B9:27:EB:3A:89:0A
```


<https://github.com/bluez/bluez/blob/master/tools/btmgmt.c>

## Secure simple pairing (sc off, ssp on)

Enable security mode 3 (secure communication before channel is established):
```
linksec on
```

Set bondable to false, so no long term keys are exhanged,
so pairing has to be done everytime connection is established.

```s
bondable false
```

```s
remote-oob -t 0 -r 90ab27c8ee20cfe07d745960b0ebc0a9 -h d0320621648302ffb4e71edd79e86bed B8:27:EB:3A:89:0A
```

```s
remote-oob -t 0 -r cece612010b4897695092b13c32e0477 -h a838b21ee01a63198e490918f79f2447 00:1A:7D:DA:71:07
```

Desktop: 00:1A:7D:DA:71:07


```
pair -c 3 -t 0 00:1A:7D:DA:71:07
```

Target should be connectable:
```
connectable on
```
