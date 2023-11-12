package api

import (
	"github.com/charmbracelet/log"
	"github.com/go-chi/chi/v5"
	"github.com/jmoiron/sqlx"
	"github.com/lu1a/go-oauth-backend-boilerplate/api/auth"
	"github.com/lu1a/go-oauth-backend-boilerplate/types"
)

func APIRouter(log log.Logger, db *sqlx.DB, config types.Config, r chi.Router) func(chi.Router) {
	return func(r chi.Router) {
		r.Route("/auth", auth.AuthRouter(log, db, config, r))
		// ...
	}
}
