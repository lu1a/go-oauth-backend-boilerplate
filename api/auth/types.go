package auth

import "github.com/lu1a/go-oauth-backend-boilerplate/db"

/*
Route: /api/auth
Type: query
*/
type IAPIAuthResponse struct {
	Account db.Account `json:"account"`
}
