package main

import (
	"bytes"
	"fmt"

	"github.com/things-go/encrypt"
)

func main() {
	password := "pass_word"
	plainText := []byte("hello world")

	cip, err := encrypt.NewCipher("aes-128-cfb", password)
	if err != nil {
		panic(err)
	}
	// encrypt
	cipherText := make([]byte, len(plainText))
	cip.Write.XORKeyStream(cipherText, plainText)
	// decrypt
	got := make([]byte, len(cipherText))
	cip.Read.XORKeyStream(got, cipherText)

	if bytes.Equal(got, plainText) {
		fmt.Println("encrypt success")
	} else {
		panic("not equal")
	}
}
