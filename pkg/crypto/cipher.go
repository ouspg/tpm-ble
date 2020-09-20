package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
)

type CipherSession struct {
	cipher cipher.AEAD
}

func NewCipherSession(sessionKey []byte) (*CipherSession, error) {
	sessionCipher := CipherSession{}

	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("could not create cipher: %s", err)
	}

	sessionCipher.cipher, err = cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("could not create GCM from block cipher: %s", err)
	}

	return &sessionCipher, nil
}

type NoncedCiphertext struct {
	Data []byte `json:"data"`
	Nonce []byte `json:"nonce"`
}

func MarshalNoncedCiphertext(src *NoncedCiphertext) ([]byte, error) {
	return json.Marshal(src)
}

func UnmarshalNoncedCiphertext(data []byte) (*NoncedCiphertext, error) {
	var dst  NoncedCiphertext
	err := json.Unmarshal(data, &dst)
	if err != nil {
		log.Warnf("Received incorrect nonced ciphertext:\n", hex.Dump(data))
		return nil, err
	}
	return &dst, nil
}

func (session *CipherSession) Encrypt(plaintext []byte) (*NoncedCiphertext, error) {
	nonce := make([]byte, session.cipher.NonceSize())
	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}
	ciphertext := session.cipher.Seal(nil, nonce, plaintext, nil)

	log.Debugf("Encrypt plaintext:\n%s\n\nNonce:\n%s\nCiphertext: \n%s",
		hex.Dump(plaintext), hex.Dump(nonce), hex.Dump(ciphertext))

	return &NoncedCiphertext{
		Data:  ciphertext,
		Nonce: nonce,
	}, nil
}

// This may fail, if the server is still sending characteristic values from the previous connection
// This has been observed to happen after reconnection
func (session *CipherSession) Decrypt(ciphertext *NoncedCiphertext) ([]byte, error) {
	plaintext, err := session.cipher.Open(nil, ciphertext.Nonce, ciphertext.Data, nil)
	if err != nil {
		log.Warnf("Decryption failed. Nonce:\n%s\nHexdump: \n%s", hex.Dump(ciphertext.Nonce), hex.Dump(ciphertext.Data))
	}
	return plaintext, err
}
