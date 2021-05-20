package goauthenticator

import (
	"testing"
	"time"
)

// This is all for testing purposes, normally you would store this information in a real database
type user struct {
	Username string
	Hash string
	Salt string
}

var userCollection []user
var sessionCollection []Session

func getUserPasswordAndSalt(username string) (string, string, error) {
	for _, user := range userCollection {
		if user.Username == username {
			return user.Hash, user.Salt, nil
		}
	}
	return "", "", nil
}

func getSessionFromDatabase(sessionToken string) (Session, error) {
	for _, session := range sessionCollection {
		if session.SessionToken == sessionToken && session.Expires < time.Now().Unix() {
			return session, nil
		}
	}
	return Session{}, nil
}

func saveSessionToDatabase(uid string, session Session) error {
	sessionCollection = append(sessionCollection, session)
	return nil
}

func TestAuthenticator(t *testing.T) {
	authenticator := NewAuthenticator(getSessionFromDatabase, saveSessionToDatabase, "/login", 32, 10000, 64, getUserPasswordAndSalt)
	password := "test123"
	t.Log("Hashing password: " + password)

	start := time.Now()

	salt := authenticator.CreateSalt()
	hash := authenticator.Hash(password, salt)
	u := user{
		Username: "test",
		Hash:     string(hash),
		Salt:     string(salt),
	}
	userCollection = append(userCollection, u)

	elapsed := time.Since(start)

	//t.Log("Hash: " + string(hash))
	t.Log("Salt: " + string(salt))
	t.Logf("Hash took %s", elapsed)

	// Test CheckPassword
	// Give it a correct password
	ok, err := authenticator.CheckPassword(u.Username, "test123")
	if err != nil {
		t.Failed()
		t.Error(err.Error())
	}
	if !ok {
		t.Failed()
		t.Error("Password validation failed while it should have succeeded")
		t.Errorf("User: %+v\n", u)
	} else {
		t.Log("Correct password check: true")
	}

	// Give it an incorrect password
	ok, err = authenticator.CheckPassword(u.Username, "test")
	if err != nil {
		t.Failed()
		t.Error(err.Error())
	}
	if ok {
		t.Failed()
		t.Error("CheckPassword says the password is correct while it is not")
		t.Errorf("User: %+v\n", u)
	} else {
		t.Log("Incorrect password check: true")
	}

	ok, err = authenticator.CheckPassword(u.Username, "")
	if err != nil {
		t.Failed()
		t.Error(err.Error())
	}
	if ok {
		t.Failed()
		t.Error("CheckPassword says the password is correct while it is not")
		t.Errorf("User: %+v\n", u)
	} else {
		t.Log("Incorrect password check: true")
	}

	ok, err = authenticator.CheckPassword("", "test123")
	if err != nil {
		t.Failed()
		t.Error(err.Error())
	}
	if ok {
		t.Failed()
		t.Error("CheckPassword says the password is correct while it is not")
		t.Errorf("User: %+v\n", u)
	} else {
		t.Log("Incorrect password check: true")
	}

	ok, err = authenticator.CheckPassword("", "")
	if err != nil {
		t.Failed()
		t.Error(err.Error())
	}
	if ok {
		t.Failed()
		t.Error("CheckPassword says the password is correct while it is not")
		t.Errorf("User: %+v\n", u)
	} else {
		t.Log("Incorrect password check: true")
	}

	ok, err = authenticator.CheckPassword("incorrectusername", "test123")
	if err != nil {
		t.Failed()
		t.Error(err.Error())
	}
	if ok {
		t.Failed()
		t.Error("CheckPassword says the password is correct while it is not")
		t.Errorf("User: %+v\n", u)
	} else {
		t.Log("Incorrect password check: true")
	}
}
