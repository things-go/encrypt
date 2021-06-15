package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var aesKeySizes = []int{16, 24, 32}

func mockErrorNewCipher([]byte) (cipher.Block, error) {
	return nil, errors.New("mock error new cipher")
}

func TestBlockModeCipher(t *testing.T) {
	plainText := []byte("helloworld,this is golang language. welcome")
	t.Run("aes", func(t *testing.T) {
		for _, keySize := range aesKeySizes {
			key := make([]byte, keySize)
			_, err := io.ReadFull(rand.Reader, key)
			require.NoError(t, err)

			blk, err := NewBlockCipher(key, aes.NewCipher,
				WithBlockRandIV(RandIV),
				WithBlockCodec(cipher.NewCBCEncrypter, cipher.NewCBCDecrypter))
			require.NoError(t, err)

			assert.Equal(t, aes.BlockSize, blk.BlockSize())

			cipherText, err := blk.Encrypt(plainText)
			require.NoError(t, err)
			want, err := blk.Decrypt(cipherText)
			require.NoError(t, err)
			assert.Equal(t, want, plainText)

			cipherText, err = blk.Encrypt(plainText)
			require.NoError(t, err)
			want, err = blk.Decrypt(cipherText)
			require.NoError(t, err)
			assert.Equal(t, want, plainText)
		}
	})
	t.Run("invalid cipher", func(t *testing.T) {
		key := make([]byte, 16)
		_, err := io.ReadFull(rand.Reader, key)
		require.NoError(t, err)

		_, err = NewBlockCipher(key, mockErrorNewCipher)
		require.Error(t, err)
	})
	t.Run("invalid iv function or length", func(t *testing.T) {
		key := make([]byte, 16)
		_, err := io.ReadFull(rand.Reader, key)
		require.NoError(t, err)

		bc, err := NewBlockCipher(key, aes.NewCipher, WithBlockRandIV(func(block cipher.Block) ([]byte, error) {
			return nil, errors.New("invalid iv")
		}))
		require.NoError(t, err)

		_, err = bc.Encrypt(plainText)
		require.Error(t, err)
	})
	t.Run("invalid input cipher text", func(t *testing.T) {
		key := make([]byte, 16)
		_, err := io.ReadFull(rand.Reader, key)
		require.NoError(t, err)

		bc, err := NewBlockCipher(key, aes.NewCipher)
		require.NoError(t, err)

		_, err = bc.Decrypt([]byte{})
		require.Error(t, err)
	})
}
