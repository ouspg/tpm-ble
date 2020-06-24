package main

import (
	"encoding/hex"
	"fmt"
	"github.com/google/go-tpm/tpm"
	"github.com/jarijaas/openssl"
	"log"
	"os"
)

var caCertPEM = `
-----BEGIN CERTIFICATE-----
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
QJbgEsc30iUHTA==
-----END CERTIFICATE-----
`

var fakeCertPEM = `
-----BEGIN CERTIFICATE-----
MIIExzCCA6+gAwIBAgIRAKc0rBDWwARPCAAAAABDVkYwDQYJKoZIhvcNAQELBQAw
QjELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFUdvb2dsZSBUcnVzdCBTZXJ2aWNlczET
MBEGA1UEAxMKR1RTIENBIDFPMTAeFw0yMDA1MjYxNTM3NDdaFw0yMDA4MTgxNTM3
NDdaMGUxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQH
Ew1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUgTExDMRQwEgYDVQQDDAsq
Lmdvb2dsZS5maTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDVoGCx6r/YzxPAd
druFKrdREQamAe1h4huzNmtOEVZX2n+V/dsBvcnB3mhrRGYh2gLb+vACj9m18V+h
yTe8jXGjggJeMIICWjAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUH
AwEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU4ewR/7BF0zOSVFnRin3su95aY64w
HwYDVR0jBBgwFoAUmNH4bhDrz5vsYJ8YkBug630J/SswZAYIKwYBBQUHAQEEWDBW
MCcGCCsGAQUFBzABhhtodHRwOi8vb2NzcC5wa2kuZ29vZy9ndHMxbzEwKwYIKwYB
BQUHMAKGH2h0dHA6Ly9wa2kuZ29vZy9nc3IyL0dUUzFPMS5jcnQwIQYDVR0RBBow
GIILKi5nb29nbGUuZmmCCWdvb2dsZS5maTAhBgNVHSAEGjAYMAgGBmeBDAECAjAM
BgorBgEEAdZ5AgUDMC8GA1UdHwQoMCYwJKAioCCGHmh0dHA6Ly9jcmwucGtpLmdv
b2cvR1RTMU8xLmNybDCCAQYGCisGAQQB1nkCBAIEgfcEgfQA8gB3AAe3XBvlfWj/
8bDGHSMVx7rmV3xXlLdq7rxhOhpp06IcAAABclHY43kAAAQDAEgwRgIhAM8BMDQ2
0ZyIPu14wjtVTRw3NZV/+wgujsogbP1Lv7LhAiEApLK0+5MdnZKbynwuTGSBNpCI
xP2lMYY6PhBz/UqcQeQAdwDGUqDsSM6z/KsXCZLEOodBMwnoAGWiYlJAG6M2KhfF
ZQAAAXJR2OEjAAAEAwBIMEYCIQCgxd1woH/H1uPrqSp/nrdwg/ytaYaeNRY4Owtm
hvRqMgIhALQ0WyX692z+y41caR95z8fIg18QRbUIYS3j9K4SK4VZMA0GCSqGSIb3
DQEBCwUAA4IBAQB2NdrKY8wvwbeh2w7dLpNHPEg9ZI9QiUJFLi+TODjAuZhybgrF
RWGZ+rn3vB0wQ5ixeXJJuziOspuliR3fdaErhdE5xdtArh20bI7DQUwoTjR1EjmL
g3v3VkQotEqbYDT+CbiMcFBk/oR7JL/EScxk+D9VnjzwJkBE2yGAxXy9XJIvYnVb
PM7uffKti5uIuX/zbBRjMF1Usy9YVGHtn3k4zF6julQB+yFVBp3TU2iqLKT1VuAy
gVgOJn2TEWKRJx9/i9dxwjgdxhlzozse/tDIFraO8ZZTUoCb9l+8TPR8M7DRO04X
Epp5r7udjl3eJiEU/4lvwuBesR9RQiqUoxDb
-----END CERTIFICATE-----
`

var receiverCertPEM = `
-----BEGIN CERTIFICATE-----
MIIDvzCCAaegAwIBAgIBATANBgkqhkiG9w0BAQsFADCBozELMAkGA1UEBhMCRkkx
GjAYBgNVBAgMEVBvaGpvaXMtUG9oamFubWFhMQ0wCwYDVQQHDARPdWx1MRswGQYD
VQQKDBJVbml2ZXJzaXR5IG9mIE91bHUxDjAMBgNVBAsMBU9VU1BHMRYwFAYDVQQD
DA1TZWNyZWRhcyBUZXN0MSQwIgYJKoZIhvcNAQkBFhVqYXJpLmphYXNrZWxhQG91
bHUuZmkwIBcNMjAwNjExMTgzNDM1WhgPMjI5NDAzMjYxODM0MzVaMA8xDTALBgNV
BAMMBHRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASqipwhqX9DvxILcIUk
AK/nhKdt8K6Mgy+eDSLMhAFuSJyBAT29VFSLKnvMPGGuxzRzoMFx9se1drRnkraa
IFYCo1owWDAdBgNVHQ4EFgQU5xdDk8HFlXtlDHSwyRT/bQz+2DkwHwYDVR0jBBgw
FoAU7w7HriCjtXYFMuO94QPooGtgfnwwCQYDVR0TBAIwADALBgNVHQ8EBAMCBaAw
DQYJKoZIhvcNAQELBQADggIBADV7QOAyu45FXwuhwUbZ1aYJ9a73uilp+ha4ZpFF
+VRVSxHQJQjbvj4q9bWpt4g5Bi5G/U5MGyl2cnJyhUwUca4ywNoJ/00ZZpEQ32Pw
y3ZlNXv9/Q1dQk1vfWNCUQ/V8yg92n9WPRrV1UyqIadlQjc9c0rfq4MklxdLtZpR
VC+Ji4OPvPGzjuOmT/e9uqM7isGFgyJ0gykW0bnw70xtjLstsD2hGw/R3l5BlDQS
Kkd0CLnTuEm2nKqUX3AsnD2tj+BgIpuUIGv7RtYc0UKVywJSB1CUGXinosTf0s9p
l9+5drbRma8Y7jBrsQuvL9FU52YJTQueD7Do5EV5Alsg7EHY8v1kSsBi8CtJahk2
oWHSx893reKIi81reZ4vP5uf+OpDcEHaDV3BP7AsNLitwLaXxB/GG37S5EZoIOHK
jDGNSe31Oh6Ruygnn7zFv4uNVFUDoEzL9nuHT8b4O/UVeffxSbc/xcTNlltL49my
s9na67Ld+0ucmKINgMRfK/rQ43mD+ymg2ht875ftv3htPkhHwdHZWkW7De2FCmIg
S7RAc9+htzJKHYcMbOFONkHQiQf8scHimiNE8WYypuENjaHpjM1/eH3nC/8Yal7G
35ui4nYwssGmiuACg/OpArjVCJuo1K0xAzJuhkCdIEmf06lN6Qs6wvQ2e3HB11m7
Onwz
-----END CERTIFICATE-----
`

var originatorCert = `
-----BEGIN CERTIFICATE-----
MIIDvzCCAaegAwIBAgIBATANBgkqhkiG9w0BAQsFADCBozELMAkGA1UEBhMCRkkx
GjAYBgNVBAgMEVBvaGpvaXMtUG9oamFubWFhMQ0wCwYDVQQHDARPdWx1MRswGQYD
VQQKDBJVbml2ZXJzaXR5IG9mIE91bHUxDjAMBgNVBAsMBU9VU1BHMRYwFAYDVQQD
DA1TZWNyZWRhcyBUZXN0MSQwIgYJKoZIhvcNAQkBFhVqYXJpLmphYXNrZWxhQG91
bHUuZmkwIBcNMjAwNjExMTgzNDM1WhgPMjI5NDAzMjYxODM0MzVaMA8xDTALBgNV
BAMMBHRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASqipwhqX9DvxILcIUk
AK/nhKdt8K6Mgy+eDSLMhAFuSJyBAT29VFSLKnvMPGGuxzRzoMFx9se1drRnkraa
IFYCo1owWDAdBgNVHQ4EFgQU5xdDk8HFlXtlDHSwyRT/bQz+2DkwHwYDVR0jBBgw
FoAU7w7HriCjtXYFMuO94QPooGtgfnwwCQYDVR0TBAIwADALBgNVHQ8EBAMCBaAw
DQYJKoZIhvcNAQELBQADggIBADV7QOAyu45FXwuhwUbZ1aYJ9a73uilp+ha4ZpFF
+VRVSxHQJQjbvj4q9bWpt4g5Bi5G/U5MGyl2cnJyhUwUca4ywNoJ/00ZZpEQ32Pw
y3ZlNXv9/Q1dQk1vfWNCUQ/V8yg92n9WPRrV1UyqIadlQjc9c0rfq4MklxdLtZpR
VC+Ji4OPvPGzjuOmT/e9uqM7isGFgyJ0gykW0bnw70xtjLstsD2hGw/R3l5BlDQS
Kkd0CLnTuEm2nKqUX3AsnD2tj+BgIpuUIGv7RtYc0UKVywJSB1CUGXinosTf0s9p
l9+5drbRma8Y7jBrsQuvL9FU52YJTQueD7Do5EV5Alsg7EHY8v1kSsBi8CtJahk2
oWHSx893reKIi81reZ4vP5uf+OpDcEHaDV3BP7AsNLitwLaXxB/GG37S5EZoIOHK
jDGNSe31Oh6Ruygnn7zFv4uNVFUDoEzL9nuHT8b4O/UVeffxSbc/xcTNlltL49my
s9na67Ld+0ucmKINgMRfK/rQ43mD+ymg2ht875ftv3htPkhHwdHZWkW7De2FCmIg
S7RAc9+htzJKHYcMbOFONkHQiQf8scHimiNE8WYypuENjaHpjM1/eH3nC/8Yal7G
35ui4nYwssGmiuACg/OpArjVCJuo1K0xAzJuhkCdIEmf06lN6Qs6wvQ2e3HB11m7
Onwz
-----END CERTIFICATE-----
`

var dummyData = "This is a secret"

func testCertificateVerification() {
	caCert, err := openssl.LoadCertificateFromPEM([]byte(caCertPEM))
	if err != nil {
		log.Fatalf("Could not load CA certificate")
	}

	receiverCert, err := openssl.LoadCertificateFromPEM([]byte(receiverCertPEM))
	if err != nil {
		log.Fatalf("Could not load CA certificate")
	}

	certStore, err := openssl.NewCertificateStore()
	if err != nil {
		log.Fatalf("Could not create certificate store")
	}

	err = certStore.AddCertificate(caCert)
	if err != nil {
		log.Fatalf("Could not add cert to cert store: %s", err)
	}

	_, verifyRes, err := receiverCert.VerifyTrustAndGetIssuerCertificate(certStore)
	if err != nil {
		log.Fatalf("Error during cert verification: %s", err)
	}
	if verifyRes != openssl.Ok {
		log.Fatalf("Certificate verification failed. VerifyResult: %d", verifyRes)
	}

	fakeCert, err := openssl.LoadCertificateFromPEM([]byte(fakeCertPEM))
	if err != nil {
		log.Fatalf("Could not load fake certificate")
	}

	_, verifyRes, err = fakeCert.VerifyTrustAndGetIssuerCertificate(certStore)
	if err != nil {
		log.Fatalf("Error during cert verification: %s", err)
	}

	if verifyRes != openssl.UnableToGetIssuerCertLocally {
		log.Fatalf("Fake cert was trusted, even though the fake cert should not be trusted")
	}
}

func deriveSharedSecret(privKey openssl.PrivateKey, peerPubKey openssl.PublicKey, engine *openssl.Engine) {

	// Note: Does not use ephemeral session key (ECDHE)
	// For this reason, this does not provide forward secrecy
	// Forward secrecy means in practice that session keys cannot be compromised
	// Even if the private key is compromised
	// Implementing forward secrecy should be unnecessary because the session is very short and private keys
	// are protected by the TPM anyway

	/*ephemeralPriv, err := openssl.GenerateECKey(openssl.Prime256v1)
	if err != nil {
		log.Fatalf("Could not generate EC privkey: %s", err)
	}*/


	secret, err := openssl.DeriveSharedSecretEngine(privKey, peerPubKey, engine)
	if err != nil {
		log.Fatalf("Could not derive shared secret: %s", err)
	}

	log.Printf("Shared secret: %s\n", hex.Dump(secret))
	// Secret should be hashed before using it as shared secret

}


func main()  {
	/**
	1. Get receiver pub key
	2. Verify that it was signed by the CA (certificate authority)
	3. If true, use ECDSA & encrypt using receiver pub key, send oob data and certificate
	4. Receiver decrypts, verifies signature
	5. Receiver sends oob data to originator if all ok
	6. oob data exhanged, proceed to bluetooth pairing

	See ECC encryption: https://cryptobook.nakov.com/asymmetric-key-ciphers/ecc-encryption-decryption
	 */

	testCertificateVerification()

	/*ctx, err := openssl.NewCtx()
	if err != nil {
		log.Fatalf("Could not create openssl ctx: %s", err)
	}*/

	/*receiverCert, err := openssl.LoadCertificateFromPEM([]byte(receiverCertPEM))
	if err != nil {
		log.Fatalf("Could not load CA certificate")
	}

	pubKey, err := receiverCert.PublicKey()
	if err != nil {
		log.Fatalf("Could not get cert pub key")
	}*/

	eng, err := openssl.EngineById("tpm2tss")
	if err != nil {
		log.Fatalf("Could not load engine: %s", err)
	}
	/*if C.ENGINE_set_default(eng.e, C.ENGINE_METHOD_ALL) == 0 {
		log.Fatalf("could not set engine as default")
	}*/

	err = openssl.SetEngineAsDefault(eng)
	if err != nil {
		log.Fatalf("could not set engine as default: %s", err)
	}

	privKey, err := openssl.EngineLoadPrivateKey(eng, "/mnt/hgfs/tpm/keys/test_priv.key")

	if err != nil {
		log.Fatalf("Could not load private key: %s", err)
	}

	dataSig, err := privKey.SignPKCS1v15(openssl.SHA256_Method, []byte("Sign me"))
	if err != nil {
		log.Fatalf("Could not sign data: %s", err)
	}

	pubKey, err := openssl.LoadPublicKeyFromPEM([]byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwkZpZUTVBGMd/iQpuGxr4DaI7/Oj
X6AnzMOvXXBz2hzVZRIQi1RaP5fA3aAv8OqlLJ4l1ycIPsbg3gFToO6VHA==
-----END PUBLIC KEY-----`))
	if err != nil {
		log.Fatalf("Could not load pub key from PEM: %s", err)
	}

	log.Println(hex.Dump(dataSig))

	deriveSharedSecret(privKey, pubKey, eng)

	log.Println("Crypto tests succeeded")
}
