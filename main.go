package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/charmbracelet/log"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Did you create and fill a '.env' file?", "err", err)
	}

	clientID := os.Getenv("GITHUB_OAUTH_CLIENT_ID")
	clientSecret := os.Getenv("GITHUB_OAUTH_CLIENT_SECRET")

	// Add my auth DB here
	dummyAuthDB := []DummySessionAccessTokenTuple{}

	fs := http.FileServer(http.Dir("public"))
	http.Handle("/", fs)

	// We will be using `httpClient` to make external HTTP requests later in our code
	httpClient := http.Client{}

	// Create a new redirect route route
	http.HandleFunc("/oauth/redirect", func(w http.ResponseWriter, r *http.Request) {
		// First, we need to get the value of the `code` query param
		err := r.ParseForm()
		if err != nil {
			fmt.Fprintf(os.Stdout, "could not parse query: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		code := r.FormValue("code")
		sessionToken := r.URL.Query().Get("session_token")
		if len(sessionToken) == 0 {
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
		res, err := httpClient.Do(req)
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
		dummyAuthDB = append(dummyAuthDB, DummySessionAccessTokenTuple)

		// Finally, send a response to redirect the user to the "welcome" page
		// TODO: Go back to whatever page they were trying to access in the first place
		w.Header().Set("Location", "/welcome.html")
		w.WriteHeader(http.StatusFound)
	})

	http.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		authHandler(w, r, dummyAuthDB)
	})

	log.Info("Starting server..")

	err = http.ListenAndServe("localhost:8080", nil)
	if err != nil {
		log.Fatal("Couldn't start the server", "err", err)
	}
}

func authHandler(w http.ResponseWriter, r *http.Request, authDB []DummySessionAccessTokenTuple) {
	// Get the session token from the query parameters
	sessionToken := r.URL.Query().Get("session_token")

	// Search for the session token in the dummyAuthDB
	var dbEntry DummySessionAccessTokenTuple
	for _, tuple := range authDB {
		if tuple.SessionToken == sessionToken {
			dbEntry = tuple
			break
		}
	}

	// Prepare the response in JSON format
	response := dbEntry

	// Convert the response to JSON
	jsonResponse, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "Error encoding JSON", http.StatusInternalServerError)
		return
	}

	// Set the content type and write the JSON response
	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(jsonResponse)
	if err != nil {
		http.Error(w, "Error responding to request", http.StatusInternalServerError)
		return
	}
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