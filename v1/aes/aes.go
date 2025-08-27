package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
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

type ID interface{ int | int64 }

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

// Encrypt encrypts the int64 id value to encrypted string id.
func Encrypt[I ID](id I) (encode string) {
	initialize()
	hd.Salt = salt
	hd.MinLength = minLength
	h, _ := hashids.NewWithData(hd)
	encode, _ = h.EncodeInt64([]int64{int64(id)})
	return
}

// Decrypt decrypts the encrypted string id to int64 id.
func Decrypt(data string) int64 {
	initialize()
	hd.Salt = salt
	hd.MinLength = minLength
	h, _ := hashids.NewWithData(hd)
	d, err := h.DecodeInt64WithError(data)
	if err != nil || len(d) < 1 {
		return -1
	}
	return d[0]
}

// DecryptBulk decrypts encrypted string id slice to int64 id slice.
// DecryptBulk will decrypt all encrypted string, skips invalid id, but still return an error if occured.
func DecryptBulk(data []string) (ret []int64, err error) {
	ret = []int64{}
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

// EncryptBulk encrypts int64 id slice to encrypted string id slice.
func EncryptBulk[I ID](data []I) (ret []string) {
	ret = make([]string, len(data))
	for i := range data {
		ret[i] = Encrypt(data[i])
	}
	return ret
}

func getStringKey(keys ...string) string {
	key := os.Getenv("AES_STRING_KEY")
	if len(keys) > 0 {
		key = keys[0]
	}
	return key
}

// EncryptString encrypt text with given key.
// If key is blank, then use default key AES_STRING_KEY in environment.
func EncryptString(text string, keys ...string) string {
	key := getStringKey(keys...)
	if key == "" {
		return ""
	}

	plaintext := []byte(text)
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return ""
	}

	ciphertext := make([]byte, len(plaintext))
	iv := os.Getenv("AES_IV_KEY")

	stream := cipher.NewCFBEncrypter(block, []byte(iv))
	stream.XORKeyStream(ciphertext, plaintext)

	return base64.URLEncoding.EncodeToString(ciphertext)
}

// DecryptString decrypt text with given key.
// If keys are blank, then use default key AES_STRING_KEY in environment.
func DecryptString(text string, keys ...string) string {
	key := getStringKey(keys...)

	ciphertext, _ := base64.URLEncoding.DecodeString(text)
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return ""
	}

	iv := os.Getenv("AES_IV_KEY")

	stream := cipher.NewCFBDecrypter(block, []byte(iv))

	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext)
}

// EncryptStringBulk returns encrypted string as a slice.
// Invalid encrypted string will not be returned.
func EncryptStringBulk(text []string, keys ...string) []string {
	var res []string
	for _, t := range text {
		enc := EncryptString(t, keys...)
		if enc != "" {
			res = append(res, enc)
		}
	}

	return res
}

// DecryptStringBulk returns decrypted string as a slice.
// Invalid decrypted string will not be returned.
func DecryptStringBulk(text []string, keys ...string) []string {
	var res []string
	for _, t := range text {
		dec := DecryptString(t, keys...)
		if dec != "" {
			res = append(res, dec)
		}
	}

	return res
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

// EncryptCMS encrypts the int64 id value to encrypted string id based on CMS AES key.
func EncryptCMS[I ID](id I) (encodeCMS string) {
	initializeCMS()
	hdCMS.Salt = saltCMS
	hdCMS.MinLength = minLengthCMS
	hCMS, _ := hashids.NewWithData(hdCMS)
	encodeCMS, _ = hCMS.EncodeInt64([]int64{int64(id)})
	return
}

// DecryptCMS decrypts the encrypted string id to int64 id based on CMS AES key.
func DecryptCMS(data string) int64 {
	initializeCMS()
	hdCMS.Salt = saltCMS
	hdCMS.MinLength = minLengthCMS
	hCMS, _ := hashids.NewWithData(hdCMS)
	decryptedCMS, err := hCMS.DecodeInt64WithError(data)
	if err != nil || len(decryptedCMS) < 1 {
		return -1
	}
	return decryptedCMS[0]
}

// DecryptCMSBulk decrypts encrypted string id slice to int64 id slice based on CMS AES key.
func DecryptCMSBulk(data []string) (ret []int64, err error) {
	ret = make([]int64, len(data))
	for i := range data {
		decrypted := DecryptCMS(data[i])
		if decrypted <= 0 {
			return nil, fmt.Errorf("DecryptCMS failed")
		}
		ret[i] = decrypted
	}
	return ret, nil
}

// EncryptCMSBulk encrypts int64 id slice to encrypted string id slice based on CMS AES key.
func EncryptCMSBulk(data []int64) (ret []string) {
	ret = make([]string, len(data))
	for i := range data {
		ret[i] = EncryptCMS(data[i])
	}
	return ret
}
