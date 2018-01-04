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
	"crypto/rand"

	"github.com/golang/snappy"
)

type hopCipher struct {
	block _cipher.Block
}

// We are going to use AES256-CBC
// the block size must be 32
const cipherBlockSize = 16

func newHopCipher(key []byte) (*hopCipher, error) {
	key = PKCS5Padding(key, cipherBlockSize)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &hopCipher{block}, nil
}

func (s *hopCipher) encrypt(msg []byte) []byte {
	defer func() {
		if err := recover(); err != nil {
			logger.Error("error encrypting:", err)
		}
	}()
	// compressing using snappy and encrypting data
	msg = append(
		msg[:cipherBlockSize],
		PKCS5Padding(
			snappy.Encode(nil, msg), cipherBlockSize,
		)...,
	)

	// generating random bytes for IV
	rand.Read(msg[:cipherBlockSize])
	// creates encrypter using block and IV
	encrypter := _cipher.NewCBCEncrypter(
		s.block, msg[:cipherBlockSize],
	)
	encrypter.CryptBlocks(
		msg[cipherBlockSize:], msg[cipherBlockSize:],
	)

	return msg
}

func (s *hopCipher) decrypt(iv []byte, ctext []byte) []byte {
	defer func() {
		if err := recover(); err != nil {
			logger.Error("panic:", err)
		}
	}()
	var err error

	decrypter := _cipher.NewCBCDecrypter(s.block, iv)
	decrypter.CryptBlocks(ctext, ctext)
	ctext = PKCS5UnPadding(ctext)

	ctext, err = snappy.Decode(nil, ctext)
	if err != nil {
		logger.Error(err)
	}
	return ctext
}

// PKCS5Padding implements PKCS5 as RFC8018 describes
func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	return append(ciphertext,
		bytes.Repeat([]byte{byte(padding)}, padding)...,
	)
}

// PKCS5UnPadding implements PKCS as RFC8018 describes.
func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}
