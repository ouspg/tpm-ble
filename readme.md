# [WIP] Secures Bluetooth Low Energy communication using Public Key Infrastructure and Trusted Platform Module

## LE Secure Connections Issue

Use of LE Secure Connections (`sc-secured`) causes disconnect after pairing (Connection Timeout 0x08), see [traces/disconnect_after_successful_encryption](traces/disconnect_after_successful_encryption). As a workaround, this project supports securing the connection on gatt level (`gatt-secured`). This also works on older BT controllers (prior to 4.2).

## Introduction

When an adversary is able
to sniff Bluetooth pairing traffic
the adversary can crack the Bluetooth security fairly
easily by brute-forcing the pairing code.

Fortunately, Bluetooth supports
pairing devices using an out-of-band mechanism.

Commonly, this is done using NFC or a QR code. This out-of-band data used to pair devices can be exchanged using any communication channel.

In this work, a BLE communication channel is secured using public-key cryptography and Trusted Platform Module (TPM). TPM is a physical device that can perform cryptographic operations and store data securely, such as private keys. In the `sc-secured` implementation, this channel is used to exchange out-of-band data
prior to pairing the devices. In the `gatt-secured` implementation, this channel is used for exchanging application data; therefore, the `gatt-secured` approach does not use security features that are defined in the bluetooth specification. 

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
3. Both parties generate ephemeral (single-use) ECDH (Elliptic-curve Diffie-Hellman) key pairs. Because these keys are single-use, even if an adversary would be able to crack a session key for one session, they would not be able to decrypt other sessions.
4. Devices exchange ECDH public key signed by the ECDSA private key (signed by the TPM)
5. Both parties send challenge (random data, 32 bytes) to each other. This is appended into the ECDH public key exchange message. This ensures that the adversary cannot establish a new session if they captured the ECDH signed public key message previously, and somehow have access to the ECDH private key.
6. Both parties verify using ECDSA public key that the received ECDH public key is signed by the verified ECDSA key.
7. Both parties compute a shared key using the ECDH keys and SHA256 hash algorithm.
8. Now both parties initialize AES-GCM encryption using this shared key. Every message uses a unique nonce and AES-GCM has built-in message integrity validation.
9. When using SC, both devices query the Bluetooth adapter for the out-of-band data and then exchange this data with the other party using this recently established secure communication channel
10. When using SC, both devices do pairing with the other party using this exchanged out-of-band data. Note that ponding should be disabled. When ponding is disabled, the pairing is forgotten when a device restarts and the above process must be completed again.

A Bluetooth device may enforce that pairing has to be completed before allowing access to a GATT service characteristic; therefore, accessing these characteristics would require completing the pairing process described above.

Because the communication is secured using the built-in out-of-band pairing mechanism in Bluetooth, the encryption
is performed on the link layer. Instead of doing encryption on GATT service level this approach was chosen because this work should be able to be incorporated into any existing Linux-based system that uses the BlueZ stack (such as raspberry pi) in a plug-in fashion.

Under the hood, Bluetooth 4.2+ uses ECDH and AES-CCM to secure the communication channel after pairing.

This software uses the tpm2 tss openssl engine, so
this software can be used without TPM also.

## VM and Raspberry Pi images

VM image used to deploy configs and binaries to RPi devices and RPi device images can be downloaded from [here](https://mega.nz/folder/X5xWBCiS#vGJeZtNkOkrEW5UD9TjtTg)

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

When testing TPM functionality without having a physical TPM, simulator can be used.

Start simulator:

```s
~/ibmtpm974/src/tpm_server &
```

In a new window, start resource manager (should be configured to run without root in prod system):

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

Use `raspi-provision-key.sh`:

```shell
NO_TPM=TRUE ./raspi-provision-key.sh REMOTE_HOSTNAME # Without TPM

./raspi-provision-key.sh REMOTE_HOSTNAME # TPM protected
```

Or follow the instructions below:

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

Create a signed certificate:

```s
openssl ca -config openssl-ca.cnf -policy signing_policy -extensions signing_req -out cert.pem -infiles req.csr
```

## Verify certificate

Confirm that the certificate was signed by the CA:

```s
openssl verify -CAfile keys/cacert.pem cert.pem
```

## Bluetooth (Tested using bluez 5.50, 5.54)

Clone this repository:

```shell
git clone --recurse-submodules https://github.com/ouspg/tpm-ble.git
```

Go to `go-bluetooth` subdir and follow the instructions in <https://github.com/muka/go-bluetooth> to generate the code for specific BlueZ version.

Or after the bluez api json has been generated:

```
make gen/clean && BLUEZ_VERSION=5.54 go run gen/srcgen/main.go full
```

Enable bluetooth:
```shell
sudo systemctl enable bluetooth && \
sudo systemctl start bluetooth
```

Add compatibility flag to the end of `ExecStart` line in `/etc/systemd/system/dbus-org.bluez.service`:

```ini
[Service]
Type=dbus
BusName=org.bluez
ExecStart=/usr/lib/bluetooth/bluetoothd -d --compat
NotifyAccess=main
```

Otherwise, you may get `Operation currently not available` error when connecting to the BT device.

Secure connections only.

In the latest raspberry pi kernel, at the time of writing, there was a bug in the bluetooth stack that
caused failure in establishing connection when sc only mode was enabled.
This was fixed in the bluetooth-next upstream.

```shell
sc only
```

## Troubleshooting

Monitor HCI and MGMT commands:

```shell
sudo btmon
```

Monitor bluetoothd:

```
tail -f /var/log/syslog
```

Monitor dmesg:

```
dmesg -w
```

Sniff BlueZ DBus:

```
sudo dbus-monitor --system "type='signal',sender='org.bluez'"
```

## Test OOB by exchanging out-of-band data manually

Get random and confirmation value for both devices:

```shell
sudo btmgmt le-oob
```

Exec in both devices to exchange these values:

```s
sudo btmgmt remote-oob -t <ADDR_TYPE> -R <RANDOM> -H <CONFIRMATION> <TARGET_HW_ADDRESS>
```

See <https://git.kernel.org/pub/scm/bluetooth/bluez.git/tree/doc/mgmt-api.txt>

## Demo (`gatt-secured`)

[![asciicast](https://asciinema.org/a/01IiWzJm0RwokcI8oC1iBX94l.svg)](https://asciinema.org/a/01IiWzJm0RwokcI8oC1iBX94l)

## Gateway (`examples/gateway`)

The gateway connects to a unsecured BLE peripheral and
creates a secured gatt service that communicates
with the unsecured peripheral and exposes characteristics of that
unsecured perhipheral in the secured gatt service.

This is only meant to be used in demos when
demonstrating securing data from a real-world BLE device is preferred.
In the final product, the traffic should be e2e secured.

This requires two bluetooth adapters. In the example,
`hci0` connects to the unsecured peripheral and
`hci1` acts as a secured gatt service.

Currently, supports notification, read and write. Does not support advertisement data or descriptions.

## Heart rate demo (`examples/heart-rate/client`)

This demo uses the gateway described above. The gateway connects to [nRF Connect](https://play.google.com/store/apps/details?id=no.nordicsemi.android.mcp) Android application,
that simulates a [heart rate peripheral](https://www.bluetooth.org/docman/handlers/downloaddoc.ashx?doc_id=239866). 

[![asciicast](https://asciinema.org/a/vt5aU3f3s6qsB9iaiEiaxzyT2.svg)](https://asciinema.org/a/vt5aU3f3s6qsB9iaiEiaxzyT2)

## FAQ

### Decryption failed

After establishing secured channel connection, this has been observed to happen sometimes after reconnection,
when the previous connection terminated because of an error.
In this case, the server does not seem to receive disconnect event and continues to send
notification messages to a client that is not connected. Because of this,
the underlying bluetooth stack seems to send these messages again after establishing a new connection, encrypted using the old session key, which causes this
"decryption failed" error.

### JSON unmarshal of received data failed (data is nil)

Observed to happen rarely when using USB bluetooth dongle (unreliable adapter?), should work after reconnection

## Acknowledgements

The research leading to these results was derived from the project SECREDAS (Product Security for Cross Domain Reliable Dependable Automated Systems) funded by ECSEL-JU (Electronic Component Systems for European Leadership Joint Undertaking) of the European Union’s Horizon 2020 research and innovation programme under grant agreement nr. 783119, and by Business Finland.
