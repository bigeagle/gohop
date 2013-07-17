package hop

import (
    "bytes"
    "crypto/aes"
    "crypto/rand"
    _cipher "crypto/cipher"
)


type hopCipher struct {
    block       _cipher.Block
}

const cipherBlockSize = 16

func newHopCipher(key []byte) (*hopCipher, error) {
    s := new(hopCipher)
    key = PKCS5Padding(key, cipherBlockSize)
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    s.block = block
    return s, nil
}

func (s *hopCipher) encrypt(msg []byte) ([]byte) {
    pmsg := PKCS5Padding(msg, cipherBlockSize)
    buf := make([]byte, len(pmsg) + cipherBlockSize)

    iv :=  buf[:cipherBlockSize]
    rand.Read(iv)
    encrypter := _cipher.NewCBCEncrypter(s.block, iv)
    encrypter.CryptBlocks(buf[cipherBlockSize:], pmsg)

    return buf
}

func (s *hopCipher) decrypt(iv []byte, ctext []byte) ([]byte) {
    decrypter := _cipher.NewCBCDecrypter(s.block, iv)
    buf := make([]byte, len(ctext))
    decrypter.CryptBlocks(buf, ctext)
    return PKCS5UnPadding(buf)
}


func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
    padding := blockSize - len(ciphertext) % blockSize
    padtext := bytes.Repeat([]byte{byte(padding)}, padding)
    return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
    length := len(origData)
    unpadding := int(origData[length-1])
    return origData[:(length - unpadding)]
}
