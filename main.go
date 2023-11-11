package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"time"

	"github.com/charmbracelet/log"
	"github.com/go-chi/chi/v5"
	"github.com/joho/godotenv"
	"github.com/lu1a/go-oauth-backend-boilerplate/auth"
)

func main() {
	log := log.New(os.Stdout)

	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Did you create and fill a '.env' file?", "err", err)
	}

	// TODO: Add my auth DB here
	dummyAuthDB := []auth.DummySessionAccessTokenTuple{}

	r := chi.NewRouter()

	mw := auth.AuthMiddleware(http.DefaultServeMux, &dummyAuthDB)
	r.Use(mw)

	r.Get("/login", func(w http.ResponseWriter, r *http.Request) {
		pageData := HomePageData{
			// TODO
		}

		_, err := getSessionToken(r)
		if err != nil {
			switch {
			case errors.Is(err, http.ErrNoCookie):
				log.Info("Session token not found, generating a new one")

				newSessionTokenBytes, err := exec.Command("uuidgen").Output()
				if err != nil {
					log.Fatal(err)
				}
				token := string(newSessionTokenBytes)
				cookie := http.Cookie{
					Name:     "session_token",
					Value:    token,
					Path:     "/",
					MaxAge:   3600,
					HttpOnly: true,
					Secure:   true,
					SameSite: http.SameSiteLaxMode,
				}
				http.SetCookie(w, &cookie)
			default:
				log.Error(err)
				http.Error(w, "server error", http.StatusInternalServerError)
				return
			}
		}
		
		fp := path.Join("templates", "login.html")
		tmpl, err := template.ParseFiles(fp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if err := tmpl.Execute(w, pageData); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		session := r.Context().Value(auth.DummySessionAccessTokenTuple{})

		fp := path.Join("templates", "index.html")
		tmpl, err := template.ParseFiles(fp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if err := tmpl.Execute(w, session); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	r.Get("/oauth/redirect", func(w http.ResponseWriter, r *http.Request) {
		githubOauthRedirectHandler(w, r, *log, &dummyAuthDB)
	})

	log.Info("Starting server..")

	err = http.ListenAndServe("localhost:8080", r)
	if err != nil {
		log.Fatal("Couldn't start the server")
	}
}

func githubOauthRedirectHandler(w http.ResponseWriter, r *http.Request, log log.Logger, authDB *[]auth.DummySessionAccessTokenTuple) {
	clientID := os.Getenv("GITHUB_OAUTH_CLIENT_ID")
	clientSecret := os.Getenv("GITHUB_OAUTH_CLIENT_SECRET")

	err := r.ParseForm()
	if err != nil {
		log.Errorf("could not parse query: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	code := r.FormValue("code")
	sessionToken, err := getSessionToken(r)
	if err != nil || len(sessionToken) == 0 {
		log.Errorf("session token missing: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// get our access token
	reqURL := fmt.Sprintf("https://github.com/login/oauth/access_token?client_id=%s&client_secret=%s&code=%s", clientID, clientSecret, code)
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
	var gitHubUser GitHubUser
	err = json.Unmarshal(gitHubBody, &gitHubUser)
	if err != nil {
		log.Errorf("Error decoding GitHub JSON: %v", err)
		return
	}
	
	// dump the session token and the access token together in a fake db
	dummySessionAccessTokenTuple := auth.DummySessionAccessTokenTuple{
		SessionToken: sessionToken,
		AccessToken:  t.AccessToken,
		Name: gitHubUser.Name,
	}
	*authDB = append(*authDB, dummySessionAccessTokenTuple)

	// TODO: Go back to whatever page they were trying to access in the first place
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func getSessionToken(r *http.Request) (string, error) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}

type HomePageData struct {
	ClientID      string
	RedirectURI   string
	SessionToken  string
	LoginLinkText string
}

type GitHubUser struct {
	AvatarURL         string    `json:"avatar_url"`
	Bio               *string   `json:"bio"`
	Blog              string    `json:"blog"`
	Company           string    `json:"company"`
	CreatedAt         time.Time `json:"created_at"`
	Email             *string   `json:"email"`
	EventsURL         string    `json:"events_url"`
	Followers         int       `json:"followers"`
	FollowersURL      string    `json:"followers_url"`
	Following         int       `json:"following"`
	FollowingURL      string    `json:"following_url"`
	GistsURL          string    `json:"gists_url"`
	GravatarID        string    `json:"gravatar_id"`
	Hireable          *bool     `json:"hireable"`
	HTMLURL           string    `json:"html_url"`
	ID                float64   `json:"id"`
	Location          string    `json:"location"`
	Login             string    `json:"login"`
	Name              string    `json:"name"`
	NodeID            string    `json:"node_id"`
	OrganizationsURL  string    `json:"organizations_url"`
	PublicGists       int       `json:"public_gists"`
	PublicRepos       int       `json:"public_repos"`
	ReceivedEventsURL string    `json:"received_events_url"`
	ReposURL          string    `json:"repos_url"`
	SiteAdmin         bool      `json:"site_admin"`
	StarredURL        string    `json:"starred_url"`
	SubscriptionsURL  string    `json:"subscriptions_url"`
	TwitterUsername   *string   `json:"twitter_username"`
	Type              string    `json:"type"`
	UpdatedAt         time.Time `json:"updated_at"`
	URL               string    `json:"url"`
}

type OAuthAccessResponse struct {
	AccessToken string `json:"access_token"`
}
