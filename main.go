package main

import (
	"errors"
	"html/template"
	"net/http"
	"os"
	"os/exec"
	"path"

	"github.com/charmbracelet/log"
	"github.com/go-chi/chi/v5"
	"github.com/joho/godotenv"
	"github.com/lu1a/go-oauth-backend-boilerplate/middleware/auth"
	"github.com/lu1a/go-oauth-backend-boilerplate/types"
)

func main() {
	log := log.New(os.Stdout)

	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Did you create and fill a '.env' file?", "err", err)
	}
	config := types.Config{
		GitHubClientID:     os.Getenv("GITHUB_OAUTH_CLIENT_ID"),
		GitHubClientSecret: os.Getenv("GITHUB_OAUTH_CLIENT_SECRET"),

		DBConnectionURL: os.Getenv("DB_CONNECTION_URL"),
	}

	// TODO: Add my auth DB here
	dummyAuthDB := []auth.DummySessionAccessTokenTuple{}

	r := chi.NewRouter()

	mw := auth.AuthMiddleware(http.DefaultServeMux, &dummyAuthDB)
	r.Use(mw)

	r.Get("/login", func(w http.ResponseWriter, r *http.Request) {
		pageData := LoginPageData{
			// TODO
		}

		_, err := auth.GetSessionToken(r)
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
		auth.GithubOauthRedirectHandler(w, r, *log, config, &dummyAuthDB)
	})

	log.Info("Starting server..")

	err = http.ListenAndServe("localhost:8080", r)
	if err != nil {
		log.Fatal("Couldn't start the server")
	}
}

type LoginPageData struct {
	ClientID      string
	RedirectURI   string
	SessionToken  string
	LoginLinkText string
}
