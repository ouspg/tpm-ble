package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
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

	return &NoncedCiphertext{
		Data:  session.cipher.Seal(nil, nonce, plaintext, nil),
		Nonce: nonce,
	}, nil
}

func (session *CipherSession) Decrypt(ciphertext *NoncedCiphertext) ([]byte, error) {
	return session.cipher.Open(nil, ciphertext.Nonce, ciphertext.Data, nil)
}
