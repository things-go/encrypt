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

// Package encrypt implement common encrypt and decrypt for stream
package encrypt

import (
	"errors"
	"strconv"
)

// error defined
var (
	ErrInputInvalidLength     = errors.New("encoded message length must be more than zero")
	ErrInputNotMoreABlock     = errors.New("decoded message length must be more than a block size")
	ErrInputNotMultipleBlocks = errors.New("decoded message length must be multiple of block size")
	ErrInvalidIvSize          = errors.New("iv length must equal block size")
	ErrUnPaddingOutOfRange    = errors.New("unPadding out of range")
)

// KeySizeError key size error
type KeySizeError int

// Error implement Error interface
func (k KeySizeError) Error() string {
	return "encrypt: invalid key size " + strconv.Itoa(int(k))
}

// IvSizeError iv size error
type IvSizeError int

// Error implement Error interface
func (i IvSizeError) Error() string {
	return "encrypt: invalid iv size " + strconv.Itoa(int(i))
}

// BlockCrypt block crypt interface
type BlockCrypt interface {
	// BlockSize returns the mode's block size.
	BlockSize() int
	// Encrypt plain text. return iv + cipher text
	Encrypt(plainText []byte) ([]byte, error)
	// Encrypt cipher text(iv + cipher text). plain text.
	Decrypt(cipherText []byte) ([]byte, error)
}
