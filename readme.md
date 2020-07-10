## Introduction

Generally, when an adversary is able
to sniff Bluetooth pairing traffic
the adversary can crack the Bluetooth security fairly
easily by brute-forcing the pairing code.

Fortunately, Bluetooth supports
pairing devices using an out-of-band mechanism.

Commonly, this is done using NFC or a QR code (for example, QR code is used by the Apple Watch). This out-of-band data used to pair devices can be exhanged using any secure communication channel.

In this work, a BLE communication channel is secured using public-key cryptography and Trusted Platform Module (TPM). This channel is used to exchange out-of-band data
prior to pairing the devices. TPM is a physical device that can perform cryptographic operations and store data securely, such as private keys.

When provisioning a TPM,
an ECDSA (Elliptic Curve Digital Signature Algorithm) key pair is generated. The private key
never leaves the TPM; therefore, an adversary
is not able to extract the private key even if they had root
access to the system. For an adversary to communicate successfully with the other party they must have access to the TPM.

The ECDSA public key is signed by a trusted Certificate Authority (CA).
The public certificate of this CA is used to verify that
the ECDSA public keys belong to trusted devices. Devices store this CA public key locally. Alternatively,
certificate pinning could be used instead of CA,
but this could complicate provisioning of new keys.

The secure communication channel is established as follows:

1. Devices exchange ECDSA public keys (certificates)
2. Both parties verify that the received certificate is signed by the CA
3. Both parties send challenge (random data) to each other. This is appended into the ECDH public key exhange message. This ensures that the adversary cannot establish a new session if they captured the ECDH signed public key message previously and somehow have access to the ECDH private key. **(todo, not implemented yet)**
4. Both parties generate ephemeral (single-use) ECDH (Elliptic-curve Diffie-Hellman) key pairs. Because these keys are single-use, even if an adversary would be able to crack a session key for one session, they would not be able to decrypt other sessions.
5. Devices exchange ECDH public key signed by the ECDSA private key (signed by the TPM)
6. Both parties verify using ECDSA public key that the received ECDH public key is signed by the verified ECDSA key.
7. Both parties compute a shared key using the ECDH keys and SHA256 hash algorithm.
8. Now both parties initialize AES-GCM encryption using this shared key. Every message uses a unique nonce and AES-GCM has built-in message integrity validation.
9. Both devices query the Bluetooth adapter for the out-of-band data and then exchange this data with the other party using this recently established secure communication channel
10. Both devices do pairing with the other party using this exchanged out-of-band data. Note that ponding should be disabled. When pondig is disabled, the pairing is forgotten when a device restarts and the above process must be completed again.

A Bluetooth device may enforce that pairing has to be completed before allowing access to a GATT service characteristic; therefore, accessing these characteristics would require completing the pairing process described above.

Because the communication is secured using the built-in out-of-band pairing mechanism in Bluetooth, the encryption
is performed on the link layer. Instead of doing encryption on GATT service level this approach was chosen because this work should be able to be incorporated into any existing Linux-based system that uses the BlueZ stack (such as raspberry pi) in a plug-in fashion.

Under the hood, Bluetooth 4.2+ uses ECDH and AES-GCM to secure the communication channel after pairing.

This work uses the tpm2 tss openssl engine, so
this software can be used without TPM also.

## Instructions (for Raspbian)

Build raspi kernel with tpm2 support enabled (check [docs/](docs/Infineon-App-Note-SLx9670-TPM2.0_Embedded_RPi_DI_SLx-ApplicationNotes-v01_03-EN.pdf) for guide)


Additional deps required to build tpm2 software:

```shell
sudo apt-get install libcurl4-openssl-dev autoconf-archive libgcrypt-20-dev \
  autoconf-archive libcmocka0 libcmocka-dev procps iproute2 build-essential git \
  pkg-config gcc libtool automake libssl-dev uthash-dev autoconf doxygen \
  libjson-c-dev libini-config-dev
```

Install tpm2-tools, tpm2-tss and tpm2-tss-engine following the INSTALL.md guides:

1. <https://github.com/tpm2-software/tpm2-tss>
2. <https://github.com/tpm2-software/tpm2-tools>
3. <https://github.com/tpm2-software/tpm2-tss-engine>

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

## Create CA

Create certificate authority. CA files should be stored in a secure environment.
Using CA isn't really necessary, could be configured to trust specific certificate instead.

```s
openssl req -x509 -config openssl-ca.cnf -newkey rsa:4096 -sha256 -nodes -out cacert.pem -outform PEM
```

## TPM key provision (pub, priv, cert)

Use `raspi-provision-key.sh` or follow the instructions below

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

```shell
sudo apt-get install bluez-tools && \
sudo systemctl enable bluetooth && \
sudo systemctl start bluetooth
```

See <https://github.com/muka/go-bluetooth> for configuring dbus

bluetooth management API docs: <https://git.kernel.org/pub/scm/bluetooth/bluez.git/tree/doc/mgmt-api.txt>

<https://lists.zephyrproject.org/g/devel/topic/29197639>

Monitor bluetooth:

```shell
sudo btmon
```

Secure connections only (4.2):

```shell
sc only
```

secure simple pairing (4.0):

```shell
ssp on
```

Get random and confirmation value:

```shell
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

Set bondable to false, so no long term keys are exchanged,
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

## Acknowledgements

The research leading to these results was derived from the project SECREDAS (Product Security for Cross Domain Reliable Dependable Automated Systems) funded by ECSEL-JU (Electronic Component Systems for European Leadership Joint Undertaking) of the European Union’s Horizon 2020 research and innovation programme under grant agreement nr. 783119, and by Business Finland.