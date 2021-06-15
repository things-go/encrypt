package main

import (
	"bytes"
	"crypto/aes"
	"fmt"

	"github.com/things-go/encrypt"
)

func main() {
	key := []byte("12e41090cd8011ebbe031717db2895df")
	plainText := []byte("im plantext plantext")

	blk, err := encrypt.NewBlockCipher(key, aes.NewCipher)
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
