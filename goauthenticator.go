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
	SaltSize int
	Iterations int
	KeyLength int
	GetUserPasswordAndSalt func(username string) (string, string, error)
}

func NewAuthenticator(getSessionFromDatabase func(sessionToken string) (Session, error), saveSessionToDatabase func(uid string, session Session) error, redirectURI string, saltSize int, iterations int, keyLength int, getUserPasswordAndSalt func(username string) (string, string, error)) Authenticator {
	return Authenticator{
		SessionHandler: SessionHandler{
			GetSessionFromDatabase: getSessionFromDatabase,
			SaveSessionToDatabase:  saveSessionToDatabase,
			Config: Config{
				RedirectURI: redirectURI,
			},
		},
		SaltSize:               saltSize,
		Iterations:             iterations,
		KeyLength:              keyLength,
		GetUserPasswordAndSalt: getUserPasswordAndSalt,
	}
}

// CheckPassword checks if the password is correct with the data from the database
func (auth *Authenticator) CheckPassword(username string, password string) (bool, error) {
	// Get the hash and salt from the database
	dbHash, dbSalt, err := auth.GetUserPasswordAndSalt(username)
	if err != nil {
		return false, err
	}

	// Hash the entered password
	hash := auth.Hash(password, []byte(dbSalt))
	if string(hash) != dbHash {
		// Hashes do not match
		return false, nil
	}

	// Hashed match
	return true, nil
}

// Create a random []byte
func (auth *Authenticator) createRandomByteArray(alphabet []byte, size int) []byte {
	b := make([]byte, size)

	rand.Seed(time.Now().UnixNano())

	for i := range b {
		b[i] = alphabet[rand.Intn(len(alphabet))]
	}

	return b
}

// CreateSalt Create a salt
func (auth *Authenticator) CreateSalt() []byte {
	return auth.createRandomByteArray([]byte("abcdefghijklmnopqrstABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*(){}[]-=_+"), auth.SaltSize)
}

// Hash hashes the password and salt using the configuration from the Authenticator object
func (auth *Authenticator) Hash(password string, salt []byte) []byte {
	//salt := auth.CreateSalt()
	hash := pbkdf2.Key([]byte(password), salt, auth.Iterations, auth.KeyLength, sha512.New)

	return hash
}
