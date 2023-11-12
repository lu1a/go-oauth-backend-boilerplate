package middleware

import (
	"context"
	"errors"
	"net/http"

	"github.com/charmbracelet/log"
	"github.com/jmoiron/sqlx"
	"github.com/lu1a/go-oauth-backend-boilerplate/api/auth"
	"github.com/lu1a/go-oauth-backend-boilerplate/db"
)

func AuthMiddleware(next http.Handler, authDB *sqlx.DB) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			// the only routes that don't need to be authed
			if r.URL.Path == "/" || r.URL.Path == "/login" || r.URL.Path == "/api/auth/oauth/redirect" {
				next.ServeHTTP(w, r)
				return
			}

			token, err := auth.GetSessionToken(r)
			if err != nil {
				switch {
				case errors.Is(err, http.ErrNoCookie):
					http.Error(w, "Not authorised, go log in", http.StatusUnauthorized)
				default:
					log.Error(err)
					http.Error(w, "server error", http.StatusInternalServerError)
				}
				return
			}

			account, err := db.GetAccountBySession(authDB, token)
			if err != nil {
				log.Error(err)
				http.Error(w, "Not authorised, go log in", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), db.Account{}, account)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
