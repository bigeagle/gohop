/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Author: Justin Wong <justin.w.xd@gmail.com>
 *
 */

package hop

import (
    "bytes"
    "crypto/aes"
    _cipher "crypto/cipher"
    "crypto/md5"
    "crypto/rand"
)

type hopCipher struct {
    block _cipher.Block
}

const cipherBlockSize = 16

func newHopCipher(key []byte) (*hopCipher, error) {
    s := new(hopCipher)
    // key = PKCS5Padding(key, cipherBlockSize)
    key1 := md5.Sum(key)
    block, err := aes.NewCipher(key1[:])
    if err != nil {
        return nil, err
    }
    s.block = block
    return s, nil
}

func (s *hopCipher) encrypt(msg []byte) []byte {
    pmsg := PKCS5Padding(msg, cipherBlockSize)
    buf := make([]byte, len(pmsg)+cipherBlockSize)

    iv := buf[:cipherBlockSize]
    rand.Read(iv)
    encrypter := _cipher.NewCBCEncrypter(s.block, iv)
    encrypter.CryptBlocks(buf[cipherBlockSize:], pmsg)

    return buf
}

func (s *hopCipher) decrypt(iv []byte, ctext []byte) []byte {
    defer func() {
        if err := recover(); err != nil {
            logger.Error("%v", err)
        }
    }()
    decrypter := _cipher.NewCBCDecrypter(s.block, iv)
    buf := make([]byte, len(ctext))
    decrypter.CryptBlocks(buf, ctext)
    return PKCS5UnPadding(buf)
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
    padding := blockSize - len(ciphertext)%blockSize
    padtext := bytes.Repeat([]byte{byte(padding)}, padding)
    return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
    length := len(origData)
    unpadding := int(origData[length-1])
    return origData[:(length - unpadding)]
}
