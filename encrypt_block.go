// Copyright [2020] [thinkgos] thinkgo@aliyun.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package encrypt

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

// BlockOption option
type BlockOption func(bs *blockBlock)

func WithBlockRandIV(generateIv func(block cipher.Block) ([]byte, error)) BlockOption {
	return func(bs *blockBlock) {
		bs.generateIv = generateIv
	}
}

func WithBlockCodec(newEncrypt, newDecrypt func(block cipher.Block, iv []byte) cipher.BlockMode) BlockOption {
	return func(bs *blockBlock) {
		bs.newEncrypt = newEncrypt
		bs.newDecrypt = newDecrypt
	}
}

// default new with newCipher and key, key should be reference newCipher required.
// newCipher support follow or implement func(key []byte) (cipher.Block, error):
// 		aes
// 		cipher
// 		des
// 		blowfish
// 		cast5
// 		twofish
// 		xtea
// 		tea
// support:
//      cbc(default): cipher.NewCBCEncrypter, cipher.NewCBCDecrypter
func NewBlockCipher(key []byte, newCipher func(key []byte) (cipher.Block, error), opts ...BlockOption) (BlockCrypt, error) {
	block, err := newCipher(key)
	if err != nil {
		return nil, err
	}
	bb := &blockBlock{
		block:      block,
		newEncrypt: cipher.NewCBCEncrypter,
		newDecrypt: cipher.NewCBCDecrypter,
	}
	for _, opt := range opts {
		opt(bb)
	}
	return bb, nil
}

type blockBlock struct {
	block      cipher.Block
	generateIv func(block cipher.Block) ([]byte, error)
	newEncrypt func(block cipher.Block, iv []byte) cipher.BlockMode
	newDecrypt func(block cipher.Block, iv []byte) cipher.BlockMode
}

func (sf *blockBlock) BlockSize() int {
	return sf.block.BlockSize()
}

// Encrypt encrypt
func (sf *blockBlock) Encrypt(plainText []byte) ([]byte, error) {
	blockSize := sf.block.BlockSize()

	ivFunc := RandIV
	if sf.generateIv != nil {
		ivFunc = sf.generateIv
	}
	iv, err := ivFunc(sf.block)
	if err != nil || len(iv) != blockSize {
		return nil, ErrInvalidIvSize
	}

	orig := PCKSPadding(plainText, blockSize)
	cipherText := make([]byte, blockSize+len(orig))
	copy(cipherText[:blockSize], iv)
	sf.newEncrypt(sf.block, iv).CryptBlocks(cipherText[blockSize:], orig)
	return cipherText, nil
}

// Decrypt decrypt
func (sf *blockBlock) Decrypt(cipherText []byte) ([]byte, error) {
	blockSize := sf.block.BlockSize()
	if len(cipherText) == 0 || len(cipherText)%blockSize != 0 {
		return nil, ErrInputNotMultipleBlocks
	}
	iv, msg := cipherText[:blockSize], cipherText[blockSize:]
	sf.newDecrypt(sf.block, iv).CryptBlocks(msg, msg)
	return PCKSUnPadding(msg)
}

// PCKSPadding PKCS#5和PKCS#7 填充
func PCKSPadding(origData []byte, blockSize int) []byte {
	padSize := blockSize - len(origData)%blockSize
	padText := bytes.Repeat([]byte{byte(padSize)}, padSize)
	return append(origData, padText...)
}

// PCKSUnPadding PKCS#5和PKCS#7 解填充
func PCKSUnPadding(origData []byte) ([]byte, error) {
	length := len(origData)
	if length == 0 {
		return nil, ErrUnPaddingOutOfRange
	}
	unPadSize := int(origData[length-1])
	if unPadSize > length {
		return nil, ErrUnPaddingOutOfRange
	}
	return origData[:(length - unPadSize)], nil
}

// RandIV generate rand iv by rand.Reader
func RandIV(block cipher.Block) ([]byte, error) {
	iv := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	return iv, nil
}
