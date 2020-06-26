package test

import (
	"github.com/ouspg/tpm-bluetooth/pkg/esys"
	"github.com/ouspg/tpm-bluetooth/pkg/tss"
	"testing"
)

func TestEsysInit(t *testing.T)  {
	t.Log("Load TSS2 private key")

	key := tss.LoadPrivateKey(`
-----BEGIN TSS2 PRIVATE KEY-----
MIHtBgZngQUKAQOgAwEBAQIBAARYAFYAIwALAAQEcgAAABAAEAADABAAIKqKnCGp
f0O/EgtwhSQAr+eEp23wroyDL54NIsyEAW5IACCcgQE9vVRUiyp7zDxhrsc0c6DB
cfbHtXa0Z5K2miBWAgSBgAB+ACDxRRCTsICR/eZdyurCmFv2nguGj+nB1X6TZt4m
XezthAAQzolyLFsl4urRc3P1Tk7qcfL7dLyoXm4WteR51BoXfWL4S+AiD1R2AiuI
m7kxN2zcwhgoz7Zs84LnVb/JxNZQm7Gistma7scy/tsJ0EU2yrsNwx7Mz9LcsCY8
-----END TSS2 PRIVATE KEY-----
`)

	t.Log("Init ESYS")

	err := esys.Init()
	if err != nil {
		t.Fatal(err)
	}

	keyHandle, err := esys.LoadKey(key)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Key handle: 0x%X", int(keyHandle))

	// esys.ECDHKeygen(keyHandle)

	err = esys.ECDHZGen(0)
	if err != nil {
		t.Fatal(err)
	}

	/*err = esys.ECDSASign(keyHandle)
	if err != nil {
		t.Fatal(err)
	}*/

}