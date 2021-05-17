package goauthenticator

type HashedPassword struct {
	Hash []byte
	Salt []byte
}
