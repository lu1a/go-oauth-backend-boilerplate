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

	"github.com/charmbracelet/log"
	"github.com/go-chi/chi/v5"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Did you create and fill a '.env' file?", "err", err)
	}

	// TODO: Add my auth DB here
	dummyAuthDB := []DummySessionAccessTokenTuple{}

	r := chi.NewRouter()
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
		token, err := getSessionToken(r)
		if err != nil {
			switch {
			case errors.Is(err, http.ErrNoCookie):
				http.Error(w, "cookie not found", http.StatusBadRequest)
				w.Header().Set("Location", "/")
			default:
				log.Error(err)
				http.Error(w, "server error", http.StatusInternalServerError)
			}
			return
		}
		session, found := authHandler(w, r, dummyAuthDB, token)
		if !found {
			http.Error(w, "Couldn't find your token in my db", http.StatusUnauthorized)
			return
		}
		
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
		githubOauthRedirectHandler(w, r, &dummyAuthDB)
	})

	log.Info("Starting server..")

	err = http.ListenAndServe("localhost:8080", r)
	if err != nil {
		log.Fatal("Couldn't start the server")
	}
}

func githubOauthRedirectHandler(w http.ResponseWriter, r *http.Request, authDB *[]DummySessionAccessTokenTuple) {
	clientID := os.Getenv("GITHUB_OAUTH_CLIENT_ID")
	clientSecret := os.Getenv("GITHUB_OAUTH_CLIENT_SECRET")

	err := r.ParseForm()
	if err != nil {
		fmt.Fprintf(os.Stdout, "could not parse query: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	code := r.FormValue("code")
	sessionToken, err := getSessionToken(r)
	if err != nil || len(sessionToken) == 0 {
		fmt.Fprintf(os.Stdout, "session token missing: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// get our access token
	reqURL := fmt.Sprintf("https://github.com/login/oauth/access_token?client_id=%s&client_secret=%s&code=%s", clientID, clientSecret, code)
	req, err := http.NewRequest(http.MethodPost, reqURL, nil)
	if err != nil {
		fmt.Fprintf(os.Stdout, "could not create HTTP request: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	req.Header.Set("accept", "application/json")

	// Send out the HTTP request
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stdout, "could not send HTTP request: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()

	// Parse the request body into the `OAuthAccessResponse` struct
	var t OAuthAccessResponse
	if err := json.NewDecoder(res.Body).Decode(&t); err != nil {
		fmt.Fprintf(os.Stdout, "could not parse JSON response: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Make a request to the GitHub API with the access token
	gitHubURL := "https://api.github.com/user"
	gitHubRequest, err := http.NewRequest("GET", gitHubURL, nil)
	if err != nil {
		fmt.Println("Error creating GitHub request:", err)
		return
	}

	// Include the access token in the Authorization header
	gitHubRequest.Header.Set("Authorization", "token "+t.AccessToken)

	// Make the request to the GitHub API
	gitHubResponse, err := http.DefaultClient.Do(gitHubRequest)
	if err != nil {
		fmt.Println("Error making GitHub request:", err)
		return
	}
	defer gitHubResponse.Body.Close()

	// Check if the GitHub response status code is OK
	if gitHubResponse.StatusCode != http.StatusOK {
		fmt.Println("Error:", gitHubResponse.Status)
		return
	}

	// Read the GitHub response body
	gitHubBody, err := io.ReadAll(gitHubResponse.Body)
	if err != nil {
		fmt.Println("Error reading GitHub response body:", err)
		return
	}

	// Parse the GitHub JSON response
	var gitHubUser GitHubUser
	err = json.Unmarshal(gitHubBody, &gitHubUser)
	if err != nil {
		fmt.Println("Error decoding GitHub JSON:", err)
		return
	}
	
	// dump the session token and the access token together in a fake db
	DummySessionAccessTokenTuple := DummySessionAccessTokenTuple{
		SessionToken: sessionToken,
		AccessToken:  t.AccessToken,
		Name: gitHubUser.Name,
	}
	*authDB = append(*authDB, DummySessionAccessTokenTuple)

	// Finally, send a response to redirect the user to the "welcome" page
	// TODO: Go back to whatever page they were trying to access in the first place
	w.Header().Set("Location", "/")
	w.WriteHeader(http.StatusFound)
}

func authHandler(w http.ResponseWriter, r *http.Request, authDB []DummySessionAccessTokenTuple, sessionToken string) (DummySessionAccessTokenTuple, bool) {
	found := false
	var dbEntry DummySessionAccessTokenTuple
	for _, tuple := range authDB {
		if tuple.SessionToken == sessionToken {
			dbEntry = tuple
			found = true
			break
		}
	}
	return dbEntry, found
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
	Name string `json:"name"`
	// Add other fields as needed based on the GitHub API response
}

type OAuthAccessResponse struct {
	AccessToken string `json:"access_token"`
}

type DummySessionAccessTokenTuple struct {
	SessionToken string `json:"session_token"`
	AccessToken string `json:"-"`
	Name string `json:"name"`
}