package goauthenticator

import (
	"testing"
	"time"
)

func Test_test(t *testing.T) {
	authenticator := Authenticator{}
	password := "test123"

	start := time.Now()

	hash, _ := authenticator.Hash(password, 32, 10000, 64)

	elapsed := time.Since(start)
	t.Logf("Hash took %s", elapsed)

	t.Log(string(hash))
}
