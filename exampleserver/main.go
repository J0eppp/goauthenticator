package main

import (
	"fmt"
	"github.com/gorilla/mux"
	"goauthenticator"
	"log"
	"net/http"
	"time"
)

var authenticator goauthenticator.Authenticator

func main() {
	database := make(map[string]goauthenticator.Session)

	authenticator = goauthenticator.Authenticator{
		SessionHandler: goauthenticator.SessionHandler{
			GetSessionFromDatabase: func(sessionToken string) goauthenticator.Session {
				user, ok := database[sessionToken]
				if !ok {
					return goauthenticator.Session{}
				}
				return user
				//return Session{sessionToken} // This function will always "find" the session token
			},
			SaveSessionToDatabase: func(uid string, session goauthenticator.Session) error {
				database[session.SessionToken] = session
				return nil
			},
			Config: goauthenticator.Config{
				RedirectURI: "/login",
			},
		},
	}

	router := mux.NewRouter().StrictSlash(false)

	protectedRouter := router.Path("/").Subrouter()

	protectedRouter.Use(authenticator.SessionHandler.ValidateSession)

	protectedRouter.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hi, I'm a protected route")
	}).Methods("GET")

	router.HandleFunc("/get", func(w http.ResponseWriter, r *http.Request) {
		session, _ := authenticator.SessionHandler.CreateSession("test")
		http.SetCookie(w, &http.Cookie{
			Name:       "sessionToken",
			Value:      session.SessionToken,
			Path:       "",
			Domain:     "",
			Expires:    time.Unix(session.Expires, 0),
			RawExpires: "",
			MaxAge:     0,
			Secure:     false,
			HttpOnly:   false,
			SameSite:   0,
			Raw:        "",
			Unparsed:   nil,
		})
		fmt.Fprintf(w, "Added cookie")
	}).Methods("GET")

	log.Println("Webserver is running")
	log.Fatal(http.ListenAndServe(":8000", router))
}