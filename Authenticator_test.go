package goauthenticator

import (
	"testing"
	"time"
)

func TestAuthenticator(t *testing.T) {
	//authenticator := Authenticator{
	//	SaltSize: 32,
	//	Iterations: 10000,
	//	KeyLength: 64,
	//}
	authenticator := NewAuthenticator(func(sessionToken string) Session { return Session{} }, func(uid string, session Session) error { return nil }, "/login", 32, 10000, 64, func(username string) (string, string, error) { return "", "", nil})
	password := "test123"
	t.Log("Hashing password: " + password)

	start := time.Now()

	hash := authenticator.Hash(password, authenticator.CreateSalt())

	elapsed := time.Since(start)

	t.Log(string(hash))
	t.Logf("Hash took %s", elapsed)
}
