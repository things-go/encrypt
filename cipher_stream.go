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
	"crypto/cipher"

	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/cast5"
	"golang.org/x/crypto/twofish"
	"golang.org/x/crypto/xtea"
)

// NewBlowfishCipher new blowfish cipher
// The key argument should be the Blowfish key, from 1 to 56 bytes.
func NewBlowfishCipher(key []byte) (cipher.Block, error) { return blowfish.NewCipher(key) }

// NewCast5Cipher new cast5 cipher,
// The key size should 32
func NewCast5Cipher(key []byte) (cipher.Block, error) { return cast5.NewCipher(key) }

// NewTwofishCipher new twofish cipher
// The key argument should be the Twofish key, 16, 24 or 32 bytes.
func NewTwofishCipher(key []byte) (cipher.Block, error) { return twofish.NewCipher(key) }

// NewXteaCipher new xtea cipher
// The key argument should be the XTEA key.
// XTEA only supports 128 bit (16 byte) keys.
func NewXteaCipher(key []byte) (cipher.Block, error) { return xtea.NewCipher(key) }
