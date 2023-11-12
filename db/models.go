package db

import "time"

type Account struct {
	AccountID    int     `json:"account_id" db:"account_id"`
	Name         string  `json:"name" db:"name"`
	Email        *string `json:"email" db:"email"`
	Location     *string `json:"location" db:"location"`
	AvatarURL    *string `json:"avatar_url" db:"avatar_url"`
	PasswordHash *string `json:"-" db:"password_hash"`
	PasswordSalt *string `json:"-" db:"password_salt"`
}

type GitHubAccountProfile struct {
	ProfileID         int       `json:"profile_id" db:"profile_id"`
	AccountID         int       `json:"account_id" db:"account_id"`
	UserProfileID     int       `json:"id" db:"user_profile_id"` // the real ID from GitHub's side
	AvatarURL         string    `json:"avatar_url" db:"avatar_url"`
	Bio               *string   `json:"bio" db:"bio"`
	Blog              string    `json:"blog" db:"blog"`
	Company           string    `json:"company" db:"company"`
	CreatedAt         time.Time `json:"created_at" db:"created_at"`
	Email             *string   `json:"email" db:"email"`
	EventsURL         string    `json:"events_url" db:"events_url"`
	Followers         int       `json:"followers" db:"followers"`
	FollowersURL      string    `json:"followers_url" db:"followers_url"`
	Following         int       `json:"following" db:"following"`
	FollowingURL      string    `json:"following_url" db:"following_url"`
	GistsURL          string    `json:"gists_url" db:"gists_url"`
	GravatarID        string    `json:"gravatar_id" db:"gravatar_id"`
	Hireable          *bool     `json:"hireable" db:"hireable"`
	HTMLURL           string    `json:"html_url" db:"html_url"`
	Location          string    `json:"location" db:"location"`
	Login             string    `json:"login" db:"login"`
	Name              string    `json:"name" db:"name"`
	NodeID            string    `json:"node_id" db:"node_id"`
	OrganizationsURL  string    `json:"organizations_url" db:"organizations_url"`
	PublicGists       int       `json:"public_gists" db:"public_gists"`
	PublicRepos       int       `json:"public_repos" db:"public_repos"`
	ReceivedEventsURL string    `json:"received_events_url" db:"received_events_url"`
	ReposURL          string    `json:"repos_url" db:"repos_url"`
	SiteAdmin         bool      `json:"site_admin" db:"site_admin"`
	StarredURL        string    `json:"starred_url" db:"starred_url"`
	SubscriptionsURL  string    `json:"subscriptions_url" db:"subscriptions_url"`
	TwitterUsername   *string   `json:"twitter_username" db:"twitter_username"`
	UserType          string    `json:"user_type" db:"user_type"`
	UpdatedAt         time.Time `json:"updated_at" db:"updated_at"`
	URL               string    `json:"url" db:"url"`
}

type Session struct {
	SessionID              int    `json:"session_id" db:"session_id"`
	SessionToken           string `json:"session_token" db:"session_token"`
	AccountID              int    `json:"account_id" db:"account_id"`
	GitHubAccountProfileID int    `json:"github_account_profile_id" db:"github_account_profile_id"`
}
