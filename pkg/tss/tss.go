package tss

import (
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"log"
)

type TSS2PrivKey struct {
	Type asn1.ObjectIdentifier
	EmptyAuth asn1.RawValue `asn1:"tag:0,explicit,optional"`
	Parent int
	PubKey []byte
	PrivKey []byte
}

// https://jan.newmarch.name/go/serialisation/chapter-serialisation.html
func LoadPrivateKey(pemData string) TSS2PrivKey {
	block, _ := pem.Decode([]byte(pemData))
	data := block.Bytes

	log.Print(hex.Dump(data))

	key := TSS2PrivKey{}

	_, err2 := asn1.Unmarshal(data, &key)
	if err2 != nil {
		log.Fatalf("Could not unmarshal PEM. Error: %s", err2)
	}

	log.Println(key.Type)
	log.Println(key.EmptyAuth)
	log.Printf("Parent: %d", key.Parent) // TPM2_RH_OWNER if 0
	log.Println(hex.Dump(key.PubKey))
	log.Println(hex.Dump(key.PrivKey))

	return key
}