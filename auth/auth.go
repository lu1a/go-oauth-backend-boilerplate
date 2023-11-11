package auth

import (
	"context"
	"errors"
	"net/http"

	"github.com/charmbracelet/log"
)

func AuthMiddleware(next http.Handler, dummyAuthDB *[]DummySessionAccessTokenTuple) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			// the only routes that don't need to be authed
			if r.URL.Path == "/login" || r.URL.Path == "/oauth/redirect" {
				next.ServeHTTP(w, r)
				return
			}

			token, err := GetSessionToken(r)
			if err != nil {
				switch {
				case errors.Is(err, http.ErrNoCookie):
					http.Redirect(w, r, "/login", http.StatusSeeOther)
				default:
					log.Error(err)
					http.Error(w, "server error", http.StatusInternalServerError)
				}
				return
			}

			session, found := AuthHandler(w, r, dummyAuthDB, token)
			if !found {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			ctx := context.WithValue(r.Context(), DummySessionAccessTokenTuple{}, session)
	
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func GetSessionToken(r *http.Request) (string, error) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}

func AuthHandler(w http.ResponseWriter, r *http.Request, authDB *[]DummySessionAccessTokenTuple, sessionToken string) (DummySessionAccessTokenTuple, bool) {
	found := false
	var dbEntry DummySessionAccessTokenTuple
	for _, tuple := range *authDB {
		if tuple.SessionToken == sessionToken {
			dbEntry = tuple
			found = true
			break
		}
	}
	return dbEntry, found
}

type DummySessionAccessTokenTuple struct {
	SessionToken string `json:"session_token"`
	AccessToken string `json:"-"`
	Name string `json:"name"`
}