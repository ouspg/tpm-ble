package main

import (
	"encoding/hex"
	"github.com/ouspg/tpm-bluetooth/pkg/btmgmt"
	"log"
)

func main()  {
	ses, err := btmgmt.CreateSession()
	if err != nil {
		log.Fatal(err)
	}


	log.Println("Created btmgmt session")

	controllers, err := ses.GetControllerIndices()
	if err != nil {
		log.Fatal(err)
	}

	if len(controllers) == 0 {
		log.Fatal("Did not find a bluetooth controller")
	}

	ses.SetController(controllers[0])

	h192, r192, h256, r256, err := ses.ReadLocalOOBData()
	if err != nil {
		log.Fatalf("Could not read local oob data: %s", err)
	}

	log.Printf("Local OOB data (h192, r192, h256, r256): (%s, %s, %s, %s)",
		hex.EncodeToString(h192[:]), hex.EncodeToString(r192[:]),
		hex.EncodeToString(h256[:]), hex.EncodeToString(r256[:]))


	ses.AddRemoteOOBData([]byte(""), btmgmt.LE_PUBLIC, nil, nil, nil, nil)

}