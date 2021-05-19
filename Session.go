package goauthenticator

type Session struct {
	SessionToken string `json:"sessionToken"`
	Expires 	int64 	`json:"expires"`
}

func (s *Session) Validate() error {
	return nil
}