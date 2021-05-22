package main

import (
	"context"
	"goauthenticator"
	"testing"
)

func TestDatabase(t *testing.T) {
	ctx := context.Background()
	db, err := NewDatabase("mongodb://localhost/goauthenticator", ctx)
	if err != nil {
		t.Failed()
		t.Error("Database connection failed")
		t.Error(err.Error())
	}

	authenticator := goauthenticator.NewAuthenticator(db.GetSessionFromDatabase, db.SaveSessionToDatabase, "/login", 32, 10000, 64, db.GetUserPasswordAndSalt)

	// Save a user
	password := "Test123"
	salt := authenticator.CreateSalt()
	hash := authenticator.Hash(password, salt)

	user := User{
		Username:     "Test",
		Hash:         string(hash),
		Salt:         string(salt),
	}

	t.Log("Saving a new user")
	err = db.SaveNewUser(user)
	if err != nil {
		t.Failed()
		t.Error("Saving the new user to the database failed")
		t.Error(err.Error())
	}

	// Create a session
	t.Log("Creating a session")
	session, err := authenticator.SessionHandler.CreateSession(user.Username)
	if err != nil {
		t.Failed()
		t.Error("Creating a new session failed")
		t.Error(err.Error())
	}

	// Get the session
	t.Log("Fetching the session from the database")
	s, err := authenticator.SessionHandler.GetSessionFromDatabase(session.SessionToken)
	if err != nil {
		t.Failed()
		t.Error("Getting the session from the database failed")
		t.Error(err.Error())
	}
	if s != session {
		t.Failed()
		t.Error("Getting the session from the database failed")
		t.Error("Session when created differs from session fetched from the database")
		t.Errorf("%+v\n", s)
		t.Errorf("%+v\n", session)

	}
}
