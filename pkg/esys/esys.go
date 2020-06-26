package esys

// #cgo LDFLAGS: -ltss2-esys -ltss2-tctildr -ltss2-mu
// #include <tss2/tss2_mu.h>
// #include <tss2/tss2_esys.h>
// #include <tss2/tss2_mu.h>
// #include <tss2/tss2_tctildr.h>
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

TPM2B_PUBLIC inPublicECC = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
								 TPMA_OBJECT_NODA |
                                 TPMA_OBJECT_DECRYPT |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {
                 .size = 0,
             },
            .parameters.eccDetail = {
                 .symmetric = {
                     .algorithm = TPM2_ALG_NULL,
                     .keyBits.aes = 128,
                     .mode.aes = TPM2_ALG_CFB,
                 },
                 .scheme = {
                      .scheme = TPM2_ALG_ECDH,
                      .details = {.ecdh = {.hashAlg = TPM2_ALG_SHA256}
                      }
                  },
                 .curveID = TPM2_ECC_NIST_P256,
                 .kdf = {.scheme = TPM2_ALG_NULL }
             },
            .unique.ecc = {
                 .x = {.size = 0,.buffer = {}},
                 .y = {.size = 0,.buffer = {}}
             }
            ,
        }
    };

TPM2B_PUBLIC primaryEccTemplate = TPM2B_PUBLIC_PRIMARY_ECC_TEMPLATE;

TSS2_RC Esys_ECDH_KeyGen_Wrapper(ESYS_CONTEXT *esysContext, ESYS_TR keyHandle, TPM2B_ECC_POINT **zPoint, TPM2B_ECC_POINT **pubPoint) {
	return Esys_ECDH_KeyGen(esysContext, keyHandle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, zPoint, pubPoint);
}

// Algorithm for TPM session param encryption
TPMT_SYM_DEF tpmSym = {.algorithm = TPM2_ALG_AES,
                            .keyBits = {.aes = 128},
                            .mode = {.aes = TPM2_ALG_CFB}
};

TPM2B_ECC_POINT inPointTest = {
        .size = 0,
        .point = {
            .x = {
                 .size =  32,
                 .buffer = {
                     0x25, 0xdb, 0x1f, 0x8b, 0xbc, 0xfa, 0xbc, 0x31,
                     0xf8, 0x17, 0x6a, 0xcb, 0xb2, 0xf8, 0x40, 0xa3,
                     0xb6, 0xa5, 0xd3, 0x40, 0x65, 0x9d, 0x37, 0xee,
                     0xd9, 0xfd, 0x52, 0x47, 0xf5, 0x14, 0xd5, 0x98
                 },
             },
            .y = {
                 .size = 32,
                 .buffer = {
                     0xed, 0x62, 0x3e, 0x3d, 0xd2, 0x09, 0x08, 0xcf,
                     0x58, 0x3c, 0x81, 0x4b, 0xbf, 0x65, 0x7e, 0x08,
                     0xab, 0x9f, 0x40, 0xff, 0xea, 0x51, 0xda, 0x21,
                     0x29, 0x8c, 0xe2, 0x4d, 0xeb, 0x34, 0x4c, 0xcc
                 }
             }
        }
    };

*/
import "C"

import (
	"errors"
	"github.com/ouspg/tpm-bluetooth/pkg/tss"
	"log"
	"unsafe"
)


var esysCtx *C.ESYS_CONTEXT
var tctiCtx *C.TSS2_TCTI_CONTEXT

var parent C.ESYS_TR

func Init() error {
	// https://www.mankier.com/3/Tss2_TctiLdr_Initialize
	// Use default device (e.g, abrmd or mssim)
	if C.Tss2_TctiLdr_Initialize(nil, &tctiCtx) != C.TSS2_RC_SUCCESS {
		return errors.New("could not initialize tcti")
	}

	if C.Esys_Initialize(&esysCtx, tctiCtx, nil) != C.TSS2_RC_SUCCESS {
		C.Tss2_TctiLdr_Finalize(&tctiCtx)
		return errors.New("could not initialize esys")
	}

	log.Println("ESYS initialized")

	if C.Esys_TR_SetAuth(esysCtx, C.ESYS_TR_RH_OWNER, nil) != C.TSS2_RC_SUCCESS {
		return errors.New("could not set owner hierarchy as auth")
	}

	var primarySensitive = C.TPM2B_SENSITIVE_CREATE{}
	primarySensitive.sensitive.userAuth.size = 0
	primarySensitive.sensitive.data.size = 0

	var allOutsideInfo = C.TPM2B_DATA{}
	allOutsideInfo.size = 0
	var allCreationPCR = C.TPML_PCR_SELECTION{}
	allCreationPCR.count = 0

	// var primaryTemplate = &C.primaryEccTemplate
	var primaryTemplate = &C.inPublicECC

	parent = C.ESYS_TR_NONE

	if C.Esys_CreatePrimary(esysCtx, C.ESYS_TR_RH_OWNER, C.ESYS_TR_PASSWORD, C.ESYS_TR_NONE, C.ESYS_TR_NONE,
		&primarySensitive, primaryTemplate, &allOutsideInfo, &allCreationPCR, &parent,
		nil, nil, nil, nil) != C.TSS2_RC_SUCCESS {
		return errors.New("could not create primary")
	}

	return nil
}


func LoadKey(key tss.TSS2PrivKey) (C.ESYS_TR, error) {
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

	if C.Esys_Load(esysCtx, parent, C.ESYS_TR_PASSWORD, C.ESYS_TR_NONE, C.ESYS_TR_NONE,
		&privKey, &pubKey, &keyHandle) != C.TSS2_RC_SUCCESS {
		return C.ESYS_TR_NONE, errors.New("could not load key")
	}

	if C.Esys_TR_SetAuth(esysCtx, keyHandle, nil) != C.TSS2_RC_SUCCESS {
		return keyHandle, errors.New("could not set key handle as auth")
	}

	return keyHandle, nil
}

// https://github.com/tpm2-software/tpm2-tss/blob/6da95b04b4f22284d5b40cc03fa19e6dc514339f/test/integration/esys-ecdh-keygen.int.c
// http://epubs.surrey.ac.uk/813932/1/SSR.pdf
// Free zPoint and pubPoint using C.Esys_Free after use
func ECDHKeygen(keyHandle C.ESYS_TR,
		zPoint **C.TPM2B_ECC_POINT, pubPoint **C.TPM2B_ECC_POINT) error {

	if C.Esys_ECDH_KeyGen_Wrapper(esysCtx, keyHandle,
		zPoint, pubPoint) != C.TSS2_RC_SUCCESS {
		return errors.New("ECDH keygen failed")
	}

	/*C.Esys_Free(unsafe.Pointer(zPoint))
	C.Esys_Free(unsafe.Pointer(pubPoint))*/

	return nil
}


func ECDSASign(keyHandle C.ESYS_TR) error {

	var digest = C.TPM2B_DIGEST{}
	digest.size = 32 // C.SHA512_DIGEST_LENGTH

	var inScheme = C.TPMT_SIG_SCHEME{}
	inScheme.scheme = C.TPM2_ALG_ECDSA

	var validation = C.TPMT_TK_HASHCHECK{}
	validation.tag = C.TPM2_ST_HASHCHECK
	validation.hierarchy = C.TPM2_RH_NULL
	validation.digest.size = 0

	var sig *C.TPMT_SIGNATURE

	if C.Esys_Sign(esysCtx, keyHandle, C.ESYS_TR_PASSWORD, C.ESYS_TR_NONE, C.ESYS_TR_NONE,
			&digest, &inScheme, &validation, &sig) != C.TSS2_RC_SUCCESS {
		return errors.New("Esys_Sign failed")
	}

	log.Println(sig)

	return nil
}


// http://epubs.surrey.ac.uk/813932/1/SSR.pdf
func ECDHZGen(keyHandle C.ESYS_TR) error {
	var outPoint *C.TPM2B_ECC_POINT

	/*var zPoint *C.TPM2B_ECC_POINT
	var pubPoint *C.TPM2B_ECC_POINT

	ECDHKeygen(keyHandle, &zPoint, &pubPoint)

	log.Println(zPoint.point.x.buffer)
	log.Println(zPoint.point.y.buffer)
	log.Println(pubPoint.point.x.buffer)
	log.Println(pubPoint.point.y.buffer)*/

	/*var session C.ESYS_TR

	if C.Esys_StartAuthSession(esysCtx, C.ESYS_TR_NONE, keyHandle, C.ESYS_TR_NONE, C.ESYS_TR_NONE, C.ESYS_TR_NONE,
		nil, C.TPM2_SE_HMAC, &C.tpmSym, C.TPM2_ALG_SHA256, &session) != C.TSS2_RC_SUCCESS {
		return errors.New("StartAuthSession failed")
	}
	log.Printf("Session handle 0x%X\n", session)*/

	if C.Esys_ECDH_ZGen(esysCtx, parent, C.ESYS_TR_PASSWORD, C.ESYS_TR_NONE, C.ESYS_TR_NONE,
		&C.inPointTest, &outPoint) != C.TSS2_RC_SUCCESS {
		return errors.New("ECDH ZGen failed")
	}

	log.Println(outPoint.point.x.buffer)
	log.Println(outPoint.point.y.buffer)

	/*C.Esys_Free(unsafe.Pointer(zPoint))
	C.Esys_Free(unsafe.Pointer(pubPoint))*/

	return nil
}
