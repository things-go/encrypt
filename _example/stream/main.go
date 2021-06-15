package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/things-go/encrypt"
)

func main() {
	key := []byte("0123456789123456")
	plainText := []byte("im plantext")

	blk, err := encrypt.NewStreamCipher(key, aes.NewCipher, encrypt.WithStreamCodec(cipher.NewCTR, cipher.NewCTR))
	if err != nil {
		panic(err)
	}

	cipherText, err := blk.Encrypt(plainText)
	if err != nil {
		panic(err)
	}
	got, err := blk.Decrypt(cipherText)
	if err != nil {
		panic(err)
	}
	if bytes.Equal(plainText, got) {
		fmt.Println("encrypt success")
	} else {
		panic("not equal")
	}
}
