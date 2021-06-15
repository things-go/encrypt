package encrypt

import (
	"crypto/cipher"
)

// StreamOption option
type StreamOption func(bs *blockStream)

func WithStreamRandIV(generateIv func(block cipher.Block) ([]byte, error)) StreamOption {
	return func(bs *blockStream) {
		bs.generateIv = generateIv
	}
}

func WithStreamCodec(newEncrypt, newDecrypt func(block cipher.Block, iv []byte) cipher.Stream) StreamOption {
	return func(bs *blockStream) {
		bs.newEncrypt = newEncrypt
		bs.newDecrypt = newDecrypt
	}
}

// NewStreamCipher new with newCipher and key
// newCipher support follow or implement func(key []byte) (cipher.Block, error):
// 		aes
// 		cipher
// 		des
// 		blowfish
// 		cast5
// 		twofish
// 		xtea
// 		tea
// block stream cipher
// support:
// 		cfb(default): cipher.NewCFBEncrypter, cipher.NewCFBDecrypter
// 		ctr: cipher.NewCTR, cipher.NewCTR
// 		ofb: cipher.NewOFB, cipher.NewOFB
func NewStreamCipher(key []byte, newCipher func(key []byte) (cipher.Block, error), opts ...StreamOption) (BlockCrypt, error) {
	block, err := newCipher(key)
	if err != nil {
		return nil, err
	}
	bs := &blockStream{
		block:      block,
		newEncrypt: cipher.NewCFBEncrypter,
		newDecrypt: cipher.NewCFBDecrypter,
	}
	for _, opt := range opts {
		opt(bs)
	}
	return bs, nil
}

type blockStream struct {
	block      cipher.Block
	generateIv func(block cipher.Block) ([]byte, error)
	newEncrypt func(block cipher.Block, iv []byte) cipher.Stream
	newDecrypt func(block cipher.Block, iv []byte) cipher.Stream
}

func (sf *blockStream) BlockSize() int {
	return sf.block.BlockSize()
}

func (sf *blockStream) Encrypt(plainText []byte) ([]byte, error) {
	if len(plainText) == 0 {
		return nil, ErrInputInvalidLength
	}
	blockSize := sf.block.BlockSize()

	ivFunc := RandIV
	if sf.generateIv != nil {
		ivFunc = sf.generateIv
	}

	iv, err := ivFunc(sf.block)
	if err != nil || len(iv) != blockSize {
		return nil, ErrInvalidIvSize
	}

	cipherText := make([]byte, blockSize+len(plainText))
	copy(cipherText[:blockSize], iv)
	sf.newEncrypt(sf.block, iv).XORKeyStream(cipherText[blockSize:], plainText)
	return cipherText, nil
}

func (sf *blockStream) Decrypt(cipherText []byte) ([]byte, error) {
	blockSize := sf.block.BlockSize()
	if len(cipherText) < blockSize {
		return nil, ErrInputNotMoreABlock
	}
	iv, msg := cipherText[:blockSize], cipherText[blockSize:]
	sf.newDecrypt(sf.block, iv).XORKeyStream(msg, msg)
	return msg, nil
}
