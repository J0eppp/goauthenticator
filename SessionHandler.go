package goauthenticator

import (
	"fmt"
	"github.com/google/uuid"
	"net/http"
	"time"
)

type Session struct {
	SessionToken string `json:"sessionToken"`
	Expires 	int64 	`json:"expires"`
}

type SessionHandler struct {
	GetSessionFromDatabase func(sessionToken string) Session
	SaveSessionToDatabase func(uid string, session Session) error
	Config Config
}

func (sh *SessionHandler) CreateSessionToken() string {
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

		s := sh.GetSessionFromDatabase(c.Value)

		if len(s.SessionToken) == 0 {
			sh.unauthorized(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}