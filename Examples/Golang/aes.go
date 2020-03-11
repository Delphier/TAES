package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"log"
)

func main() {
	encryptedText := "L/5zwPlqWDSWPy6LbQASgmZF2/cD33ecs/hHeDTUSu0="
	data, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		log.Fatal(err)
	}
	key := []byte("Key1234567890-1234567890-1234567")
	iv := []byte("1234567890123456")
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	bm := cipher.NewCBCDecrypter(block, iv)
	bm.CryptBlocks(data, data)
	data, err = pkcs7strip(data, aes.BlockSize)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(string(data))
	// Output: This is the original text
}

// https://gist.github.com/nanmu42/b838acc10d393bc51cb861128ce7f89c
// pkcs7strip remove pkcs7 padding
func pkcs7strip(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("pkcs7: Data is empty")
	}
	if length%blockSize != 0 {
		return nil, errors.New("pkcs7: Data is not block-aligned")
	}
	padLen := int(data[length-1])
	ref := bytes.Repeat([]byte{byte(padLen)}, padLen)
	if padLen > blockSize || padLen == 0 || !bytes.HasSuffix(data, ref) {
		return nil, errors.New("pkcs7: Invalid padding")
	}
	return data[:length-padLen], nil
}
