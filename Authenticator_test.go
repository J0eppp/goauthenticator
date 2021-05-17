package goauthenticator

import (
	"testing"
	"fmt"
)

func Test_test(t *testing.T) {
	auth := NewAuthenticator([]byte("abcdefghijklmnopqrstABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*(){}[]-=_+"))

	password := "test123"

	hash := auth.HashPassword(password, 32, 10000, 64)

	fmt.Println(string(hash.Hash))
}
