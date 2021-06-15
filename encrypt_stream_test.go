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

var encdec = []struct {
	enc func(block cipher.Block, iv []byte) cipher.Stream
	dec func(block cipher.Block, iv []byte) cipher.Stream
}{
	{cipher.NewCFBEncrypter, cipher.NewCFBDecrypter},
	{cipher.NewCTR, cipher.NewCTR},
	{cipher.NewOFB, cipher.NewOFB},
}

func TestBlockStream(t *testing.T) {
	t.Run("encrypt decrypt", func(t *testing.T) {
		plainText := []byte("hello world,this is golang language. welcome")
		for _, v := range encdec {
			for _, keySize := range aesKeySizes {
				key := make([]byte, keySize)
				_, err := io.ReadFull(rand.Reader, key)
				require.NoError(t, err)

				blk, err := NewStreamCipher(key, aes.NewCipher,
					WithStreamRandIV(RandIV),
					WithStreamCodec(v.enc, v.dec),
				)
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
		}
	})

	t.Run("invalid cipher text", func(t *testing.T) {
		key := make([]byte, 16)
		_, err := io.ReadFull(rand.Reader, key)
		require.NoError(t, err)

		blk, err := aes.NewCipher(key)
		require.NoError(t, err)

		stream := blockStream{
			block:      blk,
			newEncrypt: cipher.NewCFBEncrypter,
			newDecrypt: cipher.NewCFBDecrypter,
		}

		_, err = stream.Encrypt([]byte{})
		require.EqualError(t, err, ErrInputInvalidLength.Error())

		_, err = stream.Decrypt(key[:len(key)-1])
		require.EqualError(t, err, ErrInputNotMoreABlock.Error())
	})
	t.Run("invalid cipher", func(t *testing.T) {
		key := make([]byte, 16)
		_, err := io.ReadFull(rand.Reader, key)
		require.NoError(t, err)

		_, err = NewStreamCipher(key, mockErrorNewCipher)
		require.Error(t, err)
	})
	t.Run("invalid iv function or length", func(t *testing.T) {
		plainText := []byte("hello world,this is golang language. welcome")
		key := make([]byte, 16)
		_, err := io.ReadFull(rand.Reader, key)
		require.NoError(t, err)

		bc, err := NewStreamCipher(key, aes.NewCipher, WithStreamRandIV(func(block cipher.Block) ([]byte, error) {
			return nil, errors.New("invalid iv")
		}))
		require.NoError(t, err)

		_, err = bc.Encrypt(plainText)
		require.Error(t, err)
	})
}
