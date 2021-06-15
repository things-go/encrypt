# encrypt
 加密流

[![GoDoc](https://godoc.org/github.com/things-go/encrypt?status.svg)](https://godoc.org/github.com/things-go/encrypt)
[![Go.Dev reference](https://img.shields.io/badge/go.dev-reference-blue?logo=go&logoColor=white)](https://pkg.go.dev/github.com/things-go/encrypt?tab=doc)
[![Build Status](https://www.travis-ci.com/things-go/encrypt.svg?branch=master)](https://www.travis-ci.com/things-go/encrypt)
[![codecov](https://codecov.io/gh/things-go/encrypt/branch/master/graph/badge.svg)](https://codecov.io/gh/things-go/encrypt)
![Action Status](https://github.com/things-go/encrypt/workflows/Go/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/things-go/encrypt)](https://goreportcard.com/report/github.com/things-go/encrypt)
[![License](https://img.shields.io/github/license/things-go/encrypt)](https://github.com/things-go/encrypt/raw/master/LICENSE)
[![Tag](https://img.shields.io/github/v/tag/things-go/encrypt)](https://github.com/things-go/encrypt/tags)

s
## Installation

```bash
    go get github.com/things-go/encrypt
```

## Import:

```go
    import "github.com/things-go/encrypt"
```

## Example

[embedmd]:# (_example/block/main.go go)
```go
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
```

[embedmd]:# (_example/stream/main.go go)
```go
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
```

[embedmd]:# (_example/cipher/main.go go)
```go
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
```

## License

This project is under MIT License. See the [LICENSE](LICENSE) file for the full license text.
