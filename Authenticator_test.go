package goauthenticator

import (
	"fmt"
	"testing"
)

func Test_test(t *testing.T) {
	password := "test123"

	hash, _ := Hash(password, 32, 10000, 64)

	fmt.Println(string(hash))
}
