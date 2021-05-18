package goauthenticator

import (
	"crypto/sha512"
	"golang.org/x/crypto/pbkdf2"
	"math/rand"
	"time"
)

/*type Authenticator struct {
	alphabet []byte
}

func (auth *Authenticator) createRandomString(size int) []byte {
	b := make([]byte, size)

	rand.Seed(time.Now().UnixNano())

	for i := range b {
		b[i] = byte(auth.alphabet[rand.Intn(len(auth.alphabet))])
	}

	return b
}

func (auth *Authenticator) HashPassword(password string, saltSize int, iterations int, keyLength int) HashedPassword {
	var hashedPassword HashedPassword

	salt := auth.createRandomString(saltSize)

	hash := pbkdf2.Key([]byte(password), salt, iterations, keyLength, sha512.New)

	hashedPassword.Hash = hash
	hashedPassword.Salt = salt

	return hashedPassword
}

func NewAuthenticator(alphabet []byte) Authenticator {
	return Authenticator{
		alphabet: alphabet,
	}
}*/

func CreateRandomByteArray(alphabet []byte, size int) []byte {
	b := make([]byte, size)

	rand.Seed(time.Now().UnixNano())

	for i := range b {
		b[i] = alphabet[rand.Intn(len(alphabet))]
	}

	return b
}

func Hash(password string, saltSize int, iterations int, keyLength int) ([]byte, []byte) {
	salt := CreateRandomByteArray([]byte("abcdefghijklmnopqrstABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*(){}[]-=_+"), saltSize)
	hash := pbkdf2.Key([]byte(password), salt, iterations, keyLength, sha512.New)

	return hash, salt
}
