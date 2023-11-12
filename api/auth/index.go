package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"

	"github.com/charmbracelet/log"
	"github.com/go-chi/chi/v5"
	"github.com/jmoiron/sqlx"
	"github.com/lu1a/go-oauth-backend-boilerplate/db"
	"github.com/lu1a/go-oauth-backend-boilerplate/types"
)

func AuthRouter(log log.Logger, dbInstance *sqlx.DB, config types.Config, r chi.Router) func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			session := r.Context().Value(db.Account{})
			if session == nil {
				http.Error(w, "Session not found", http.StatusNotFound)
			}

			sessionJSON, err := json.Marshal(session)
			if err != nil {
				http.Error(w, "Error encoding session to JSON", http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			_, err = w.Write(sessionJSON)
			if err != nil {
				http.Error(w, "Error writing out session JSON", http.StatusNotFound)
			}
		})
		r.Get("/oauth/redirect", func(w http.ResponseWriter, r *http.Request) {
			GithubOauthRedirectHandler(w, r, log, dbInstance, config)
		})
	}
	// ...

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

	newSessionTokenBytes, err := exec.Command("uuidgen").Output()
	if err != nil {
		log.Fatal(err)
	}
	sessionToken := string(newSessionTokenBytes)
	cookie := http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, &cookie)

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
