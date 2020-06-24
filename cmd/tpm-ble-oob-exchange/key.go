package main

import (
	"encoding/asn1"
	"fmt"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil/mssim"
	"log"
	"os"
)



// https://github.com/tpm2-software/tpm2-tools/issues/1599
/**
 TPMKey ::= SEQUENCE {
    type            OBJECT IDENTIFIER,
    emptyAuth       [0] EXPLICIT BOOLEAN OPTIONAL,
    parent          INTEGER,
    pubkey          OCTET STRING,
    privkey         OCTET STRING
}
 */


func main() {



	// rwc, err := tpm.OpenTPM("/dev/tpm")
	rwc, err := mssim.Open(mssim.Config{
		CommandAddress:  "localhost:2321",
		PlatformAddress: "localhost:2322",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't open the TPM file: %s", err)
		return
	}
	defer rwc.Close()

	log.Println("Opened TPM")

	/*handles, err := tpm.GetKeys(rwc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't enumerate loaded TPM keys: %s\n", err)
		return
	}

	fmt.Printf("%d keys loaded in the TPM\n", len(handles))
	for i, h := range handles {
		fmt.Printf("  (%d) Key handle %d\n", i+1, h)
	}*/

	/*blob, err := ioutil.ReadFile("/home/tpm/obj.priv")
	if err != nil {
		log.Fatalf("Could not read keyblob. Error: %s", err)
	}


	log.Println(hex.Dump(blob))*/

	/*keyHandle, err := tpm.LoadKey2(rwc, blob, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not load keyblob: %s\n", err)
		return
	}
	defer tpm.CloseKey(rwc, keyHandle)*/


	err = tpm2.Startup(rwc, tpm2.StartupClear)
	if err != nil {
		log.Fatalf("Could not startup tpm2. Error: %s", err)
	}

	_, _, err = tpm2.Load(rwc, tpm2.HandleOwner, "", key.PubKey, key.PrivKey)
	if err != nil {
		log.Fatalf("Could not load key. Error: %s\n", err)
	}

	log.Println("Loaded key handle")

}