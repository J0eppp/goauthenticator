package goauthenticator

import (
	"crypto/sha512"
	"golang.org/x/crypto/pbkdf2"
	"math/rand"
	"time"
)

type Config struct {
	RedirectURI string

}

type Authenticator struct {
	SessionHandler SessionHandler
	//Config Config
}


func (auth *Authenticator) CreateRandomByteArray(alphabet []byte, size int) []byte {
	b := make([]byte, size)

	rand.Seed(time.Now().UnixNano())

	for i := range b {
		b[i] = alphabet[rand.Intn(len(alphabet))]
	}

	return b
}

func (auth *Authenticator) Hash(password string, saltSize int, iterations int, keyLength int) ([]byte, []byte) {
	salt := auth.CreateRandomByteArray([]byte("abcdefghijklmnopqrstABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*(){}[]-=_+"), saltSize)
	hash := pbkdf2.Key([]byte(password), salt, iterations, keyLength, sha512.New)

	return hash, salt
}
