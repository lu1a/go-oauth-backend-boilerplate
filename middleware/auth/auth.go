package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/charmbracelet/log"
	"github.com/jmoiron/sqlx"
	"github.com/lu1a/go-oauth-backend-boilerplate/db"
	"github.com/lu1a/go-oauth-backend-boilerplate/types"
)

func AuthMiddleware(next http.Handler, authDB *sqlx.DB) func(next http.Handler) http.Handler {
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

			account, err := db.GetAccountBySession(authDB, token)
			if err != nil {
				log.Error(err)
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			ctx := context.WithValue(r.Context(), db.Account{}, account)

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

func GithubOauthRedirectHandler(w http.ResponseWriter, r *http.Request, log log.Logger, authDB *sqlx.DB, config types.Config) {
	err := r.ParseForm()
	if err != nil {
		log.Errorf("could not parse query: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	code := r.FormValue("code")
	sessionToken, err := GetSessionToken(r)
	if err != nil || len(sessionToken) == 0 {
		log.Errorf("session token missing: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// get our access token
	reqURL := fmt.Sprintf("https://github.com/login/oauth/access_token?client_id=%s&client_secret=%s&code=%s", config.GitHubClientID, config.GitHubClientSecret, code)
	req, err := http.NewRequest(http.MethodPost, reqURL, nil)
	if err != nil {
		log.Errorf("could not create HTTP request: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	req.Header.Set("accept", "application/json")

	// Send out the HTTP request
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Errorf("could not send HTTP request: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()

	// Parse the request body into the `OAuthAccessResponse` struct
	var t OAuthAccessResponse
	if err := json.NewDecoder(res.Body).Decode(&t); err != nil {
		log.Errorf("could not parse JSON response: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Make a request to the GitHub API with the access token
	gitHubURL := "https://api.github.com/user"
	gitHubRequest, err := http.NewRequest("GET", gitHubURL, nil)
	if err != nil {
		log.Errorf("Error creating GitHub request: %v", err)
		return
	}

	// Include the access token in the Authorization header
	gitHubRequest.Header.Set("Authorization", "token "+t.AccessToken)

	// Make the request to the GitHub API
	gitHubResponse, err := http.DefaultClient.Do(gitHubRequest)
	if err != nil {
		log.Errorf("Error making GitHub request: %v", err)
		return
	}
	defer gitHubResponse.Body.Close()

	// Check if the GitHub response status code is OK
	if gitHubResponse.StatusCode != http.StatusOK {
		log.Errorf("GitHub status not ok: %v", gitHubResponse.Status)
		return
	}

	// Read the GitHub response body
	gitHubBody, err := io.ReadAll(gitHubResponse.Body)
	if err != nil {
		log.Errorf("Error reading GitHub response body: %v", err)
		return
	}

	// Parse the GitHub JSON response
	var gitHubUser db.GitHubAccountProfile
	err = json.Unmarshal(gitHubBody, &gitHubUser)
	if err != nil {
		log.Errorf("Error decoding GitHub JSON: %v", err)
		return
	}

	err = db.UpsertAccountViaGitHub(authDB, t.AccessToken, sessionToken, gitHubUser)
	if err != nil {
		log.Errorf("Couldn't upsert user to db: %v", err)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// TODO: Go back to whatever page they were trying to access in the first place
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

type OAuthAccessResponse struct {
	AccessToken string `json:"access_token"`
}

type DummySessionAccessTokenTuple struct {
	SessionToken string `json:"session_token"`
	AccessToken  string `json:"-"`
	Name         string `json:"name"`
}
