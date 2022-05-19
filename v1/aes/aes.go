package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"

	"github.com/speps/go-hashids"
)

var hd *hashids.HashIDData
var salt string
var minLength int
var hdCMS *hashids.HashIDData
var saltCMS string
var minLengthCMS int
var ErrDecryptInvalid = errors.New("decrypt failed")

func initialize() {
	if hd != nil {
		return
	}

	hd = hashids.NewData()
	salt = os.Getenv("AES_KEY")
	minLengthStr := os.Getenv("AES_MIN_LENGTH")

	if salt == "" || minLengthStr == "" {
		log.Println("aes: env not found: AES_KEY or AES_MIN_LENGTH")
	}

	minLength, _ = strconv.Atoi(minLengthStr)
}

// Encrypt Function
func Encrypt(id int) string {
	initialize()
	hd.Salt = salt
	hd.MinLength = minLength
	h, _ := hashids.NewWithData(hd)
	encoded, _ := h.Encode([]int{id})
	return encoded
}

// Decrypt Function
func Decrypt(data string) int {
	initialize()
	hd.Salt = salt
	hd.MinLength = minLength
	h, _ := hashids.NewWithData(hd)
	d, err := h.DecodeWithError(data)
	if err != nil || len(d) < 1 {
		return -1
	}
	return d[0]
}

// DecryptBulk Function
func DecryptBulk(data []string) (ret []int, err error) {
	for i := range data {
		decrypted := Decrypt(data[i])
		if decrypted <= 0 {
			err = ErrDecryptInvalid
			continue
		}
		ret = append(ret, decrypted)
	}
	return ret, err
}

// EncryptBulk Function
func EncryptBulk(data []int) (ret []string) {
	ret = make([]string, len(data))
	for i := range data {
		ret[i] = Encrypt(data[i])
	}
	return ret
}

// EncryptString ...
func EncryptString(data []byte) ([]byte, error) {
	block, _ := aes.NewCipher([]byte(os.Getenv("AES_STRING_KEY")))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// DecryptString ...
func DecryptString(data []byte) ([]byte, error) {
	key := []byte(os.Getenv("AES_STRING_KEY"))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("invalid")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func initializeCMS() {
	if hdCMS != nil {
		return
	}

	hdCMS = hashids.NewData()
	saltCMS = os.Getenv("AES_KEY_CMS")
	minLengthStrCMS := os.Getenv("AES_MIN_LENGTH_CMS")

	if saltCMS == "" || minLengthStrCMS == "" {
		log.Println("aes: env not found: AES_KEY_CMS or AES_MIN_LENGTH_CMS")
	}

	minLengthCMS, _ = strconv.Atoi(minLengthStrCMS)
}

// EncryptCMS Function
func EncryptCMS(id int) string {
	initializeCMS()
	hdCMS.Salt = saltCMS
	hdCMS.MinLength = minLengthCMS
	hCMS, _ := hashids.NewWithData(hdCMS)
	encodedCMS, _ := hCMS.Encode([]int{id})
	return encodedCMS
}

// DecryptCMS Function
func DecryptCMS(data string) int {
	initializeCMS()
	hdCMS.Salt = saltCMS
	hdCMS.MinLength = minLengthCMS
	hCMS, _ := hashids.NewWithData(hdCMS)
	decryptedCMS, err := hCMS.DecodeWithError(data)
	if err != nil || len(decryptedCMS) < 1 {
		return -1
	}
	return decryptedCMS[0]
}

// DecryptCMSBulk Function
func DecryptCMSBulk(data []string) (ret []int, err error) {
	ret = make([]int, len(data))
	for i := range data {
		decrypted := DecryptCMS(data[i])
		if decrypted <= 0 {
			return nil, fmt.Errorf("DecryptCMS failed")
		}
		ret[i] = decrypted
	}
	return ret, nil
}

// EncryptCMSBulk Function
func EncryptCMSBulk(data []int) (ret []string) {
	ret = make([]string, len(data))
	for i := range data {
		ret[i] = EncryptCMS(data[i])
	}
	return ret
}
