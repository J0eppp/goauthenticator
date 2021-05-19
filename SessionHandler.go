package goauthenticator

import (
	"fmt"
	"github.com/google/uuid"
	"log"
	"net/http"
	"time"
)

type SessionHandler struct {
	GetSessionFromDatabase func(sessionToken string) Session
	SaveSessionToDatabase func(uid string, session Session) error
	Config Config
}

func (sh *SessionHandler) CreateSessionToken() string {
	//return uuid.New().String()
	return uuid.NewString()
}


func (sh *SessionHandler) CreateSession(uid string) (Session, error) {
	token := sh.CreateSessionToken()
	session := Session{
		SessionToken: token,
		Expires:      time.Now().Add(time.Hour * 6).Unix(),
	}
	return session, sh.SaveSessionToDatabase(uid, session)
}

func (sh *SessionHandler) unauthorized(w http.ResponseWriter) {
	w.Header().Add("Location", sh.Config.RedirectURI)
	w.WriteHeader(401) // Unauthorized
	fmt.Fprintf(w, "Unauthorized")
}

func (sh *SessionHandler) ValidateSession(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("sessionToken")
		if err != nil {
			sh.unauthorized(w)
			return
		}
		log.Println(c.Value)
		s := sh.GetSessionFromDatabase(c.Value)
		log.Printf("%+v\n", s)
		if len(s.SessionToken) == 0 {
			sh.unauthorized(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}