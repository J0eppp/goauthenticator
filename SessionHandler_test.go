package goauthenticator

import (
	"fmt"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"
	"time"
)

var authenticator Authenticator

func startWebServer(t *testing.T) {
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

	t.Log("Webserver is running")
	log.Fatal(http.ListenAndServe(":8000", router))
}

func TestSessionHandler(t *testing.T) {
	database := make(map[string]Session)

	authenticator = Authenticator{
		SessionHandler: SessionHandler{
			GetSessionFromDatabase: func(sessionToken string) (Session, error) {
				user, ok := database[sessionToken]
				if !ok {
					return Session{}, nil
				}
				return user, nil
			},
			SaveSessionToDatabase: func(uid string, session Session) error {
				database[session.SessionToken] = session
				return nil
			},
			Config: Config{
				RedirectURI: "/login",
			},
		},
	}

	//t.Logf("%+v\n", authenticator)

	//t.Log(authenticator.SessionHandler.CreateSession("test"))

	//t.Log(authenticator.SessionHandler.CreateSessionToken())

	//t.Logf("%+v\n", database)

	//go startWebServer(t)

	// HTTP test
	resp, err := http.Get("http://localhost:8000")
	if err != nil {
		t.Failed()
		t.Error("Did you run the example server?")
		t.Error(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 401 {
		// This should be unauthorized because we did not give a valid cookie
		t.Failed()
		t.Error("Server did not respond with 401 unauthorized when making an unauthorized requets to a protected route")
		//t.Errorf("%+v\n", resp)
	}

	resp, err = http.Get("http://localhost:8000/get") // get token
	if err != nil {
		t.Failed()
		t.Error(err)
	}
	defer resp.Body.Close()

	if len(resp.Cookies()) == 0 {
		// Server did not add any cookies
		t.Failed()
		t.Error("Server did not respond with a cookie")
	}

	cookies := resp.Cookies()

	client := http.Client{}
	jar, _ := cookiejar.New(nil)
	u, _ := url.Parse("http://localhost:8000")
	jar.SetCookies(u, cookies)
	client.Jar = jar
	req, _ := http.NewRequest("GET", "http://localhost:8000/", nil) // request protected route with correct session token
	resp, err = client.Do(req)
	if resp.StatusCode != 200 {
		t.Failed()
		t.Error("Server responded with a non 200 OK response code")
	}

	client = http.Client{}
	jar, _ = cookiejar.New(nil)
	u, _ = url.Parse("http://localhost:8000")
	var c []*http.Cookie
	cookie := &http.Cookie{
		Name: "sessionToken",
		Value: "invalidToken",
		Expires: time.Now().Add(time.Hour * 6),
	}
	c = append(c, cookie)
	jar.SetCookies(u, c)
	client.Jar = jar
	req, _ = http.NewRequest("GET", "http://localhost:8000/", nil) // request protected route with correct session token
	resp, err = client.Do(req)
	if resp.StatusCode != 401 {
		// Should be unauthorized, because the token "invalidToken" is not valid
		t.Failed()
		t.Error("Server responded with a non 401 Unauthorized response code but should have responded with 401 Unauthorized")
	}
}
