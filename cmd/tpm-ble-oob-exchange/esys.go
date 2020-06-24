package main

// #cgo LDFLAGS: -ltss2-esys -ltss2-tctildr -ltss2-mu
// #include <tss2/tss2_mu.h>
// #include <tss2/tss2_esys.h>
// #include <tss2/tss2_mu.h>
// #include <tss2/tss2_tctildr.h>
// #include <string.h>
/*

#define ENGINE_HASH_ALG TPM2_ALG_SHA256

#define TPM2B_PUBLIC_PRIMARY_ECC_TEMPLATE { \
    .publicArea = { \
        .type = TPM2_ALG_ECC, \
        .nameAlg = ENGINE_HASH_ALG, \
        .objectAttributes = (TPMA_OBJECT_USERWITHAUTH | \
                             TPMA_OBJECT_RESTRICTED | \
                             TPMA_OBJECT_DECRYPT | \
                             TPMA_OBJECT_NODA | \
                             TPMA_OBJECT_FIXEDTPM | \
                             TPMA_OBJECT_FIXEDPARENT | \
                             TPMA_OBJECT_SENSITIVEDATAORIGIN), \
        .authPolicy = { \
             .size = 0, \
         }, \
        .parameters.eccDetail = { \
             .symmetric = { \
                 .algorithm = TPM2_ALG_AES, \
                 .keyBits.aes = 128, \
                 .mode.aes = TPM2_ALG_CFB, \
              }, \
             .scheme = { \
                .scheme = TPM2_ALG_NULL, \
                .details = {} \
             }, \
             .curveID = TPM2_ECC_NIST_P256, \
             .kdf = { \
                .scheme = TPM2_ALG_NULL, \
                .details = {} \
             }, \
         }, \
        .unique.ecc = { \
             .x.size = 0, \
             .y.size = 0 \
         } \
     } \
}

TPM2B_PUBLIC primaryEccTemplate = TPM2B_PUBLIC_PRIMARY_ECC_TEMPLATE;
*/
import "C"

import (
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"log"
	"unsafe"
)

type TSS2PrivKey struct {
	Type asn1.ObjectIdentifier
	EmptyAuth asn1.RawValue `asn1:"tag:0,explicit,optional"`
	Parent int
	PubKey []byte
	PrivKey []byte
}

// https://jan.newmarch.name/go/serialisation/chapter-serialisation.html
func loadPEM(pemData string) TSS2PrivKey {
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


func ESYSInit() (*C.ESYS_CONTEXT, *C.TSS2_TCTI_CONTEXT) {

	var tctiCtx *C.TSS2_TCTI_CONTEXT
	var esysCtx *C.ESYS_CONTEXT

	// https://www.mankier.com/3/Tss2_TctiLdr_Initialize
	if C.Tss2_TctiLdr_Initialize(nil, &tctiCtx) != C.TSS2_RC_SUCCESS {
		log.Fatalf("could not initialize tcti")
	}

	if C.Esys_Initialize(&esysCtx, tctiCtx, nil) != C.TSS2_RC_SUCCESS {
		C.Tss2_TctiLdr_Finalize(&tctiCtx)
		log.Fatalf("could not initialize esys")
	}

	log.Println("ESYS initialized")

	// zero auth
	if C.Esys_TR_SetAuth(esysCtx, C.ESYS_TR_RH_OWNER, nil) != C.TSS2_RC_SUCCESS {
		log.Fatalf("could not set owner hierarchy auth")
	}

	var primarySensitive = C.TPM2B_SENSITIVE_CREATE{}
	primarySensitive.sensitive.userAuth.size = 0
	primarySensitive.sensitive.data.size = 0

	var allOutsideInfo = C.TPM2B_DATA{}
	allOutsideInfo.size = 0
	var allCreationPCR = C.TPML_PCR_SELECTION{}
	allCreationPCR.count = 0

	var primaryTemplate = &C.primaryEccTemplate

	var parent C.ESYS_TR
	parent = C.ESYS_TR_NONE

	if C.Esys_CreatePrimary(esysCtx, C.ESYS_TR_RH_OWNER, C.ESYS_TR_PASSWORD, C.ESYS_TR_NONE, C.ESYS_TR_NONE,
		&primarySensitive, primaryTemplate, &allOutsideInfo, &allCreationPCR, &parent, nil, nil, nil, nil) != C.TSS2_RC_SUCCESS {
		log.Fatalf("Could not create primary")
	}

	log.Println("Created primary")

	key := loadPEM(`
-----BEGIN TSS2 PRIVATE KEY-----
MIHtBgZngQUKAQOgAwEBAQIBAARYAFYAIwALAAQEcgAAABAAEAADABAAIKqKnCGp
f0O/EgtwhSQAr+eEp23wroyDL54NIsyEAW5IACCcgQE9vVRUiyp7zDxhrsc0c6DB
cfbHtXa0Z5K2miBWAgSBgAB+ACDxRRCTsICR/eZdyurCmFv2nguGj+nB1X6TZt4m
XezthAAQzolyLFsl4urRc3P1Tk7qcfL7dLyoXm4WteR51BoXfWL4S+AiD1R2AiuI
m7kxN2zcwhgoz7Zs84LnVb/JxNZQm7Gistma7scy/tsJ0EU2yrsNwx7Mz9LcsCY8
-----END TSS2 PRIVATE KEY-----
`)

	var keyHandle C.ESYS_TR
	keyHandle = C.ESYS_TR_NONE

	var pubKey = C.TPM2B_PUBLIC{}
	var privKey = C.TPM2B_PRIVATE{}

	var offset C.ulong

	offset = 0
	C.Tss2_MU_TPM2B_PUBLIC_Unmarshal((*C.uint8_t)(unsafe.Pointer(&key.PubKey[0])), C.size_t(len(key.PubKey)),
		&offset, &pubKey)

	offset = 0
	C.Tss2_MU_TPM2B_PRIVATE_Unmarshal((*C.uint8_t)(unsafe.Pointer(&key.PrivKey[0])), C.size_t(len(key.PrivKey)),
		&offset, &privKey)

	C.Esys_Load(esysCtx, parent, C.ESYS_TR_PASSWORD, C.ESYS_TR_NONE, C.ESYS_TR_NONE,
		&privKey, &pubKey, &keyHandle)

	return esysCtx, tctiCtx
}

func main()  {

	ESYSInit()
}