package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"hash"
	"io"

	"golang.org/x/crypto/hkdf"
)

func SecureRandomBytes(length int32) ([]byte, error) {
	secureRandomBytes := make([]byte, length)
	_, err := rand.Read(secureRandomBytes)
	if err != nil {
		return nil, err
	}
	return secureRandomBytes, nil
}

func Hkdf(hash func() hash.Hash, secret []byte, salt []byte, info []byte, length int) []byte {
	key := make([]byte, length)
	kdf := hkdf.New(hash, secret, salt, info)
	io.ReadFull(kdf, key)
	return key
}

func Pkcs7Pad(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, errors.New("pkcs7: invalid block size")
	}

	length := len(data)

	if data == nil || length == 0 {
		return nil, errors.New("pkcs7: invalid data")
	}

	n := blockSize - (length % blockSize)
	return append(data, bytes.Repeat([]byte{byte(n)}, n)...), nil
}

func Pkcs7Strip(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, errors.New("pkcs7: invalid block size")
	}

	length := len(data)

	if data == nil || length == 0 {
		return nil, errors.New("pkcs7: invalid data")
	}

	if length%blockSize != 0 {
		return nil, errors.New("pkcs7: invalid padding")
	}

	c := data[length-1]
	paddingLength := int(c)

	if paddingLength == 0 || paddingLength > length {
		return nil, errors.New("pkcs7: invalid padding")
	}

	for i := 0; i < paddingLength; i++ {
		if data[length-paddingLength+i] != c {
			return nil, errors.New("pkcs7: invalid padding")
		}
	}
	return data[:length-paddingLength], nil
}

func Aes256Encrypt(plaintext []byte, key []byte, iv []byte) ([]byte, error) {
	plaintextWithPadding, err := Pkcs7Pad(plaintext, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	block, _ := aes.NewCipher(key)
	ciphertext := make([]byte, len(plaintextWithPadding))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintextWithPadding)
	return ciphertext, nil
}

func Aes256Decrypt(ciphertext []byte, key []byte, iv []byte) ([]byte, error) {
	block, _ := aes.NewCipher(key)
	plaintextWithPadding := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintextWithPadding, ciphertext)

	plaintext, err := Pkcs7Strip(plaintextWithPadding, aes.BlockSize)

	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
