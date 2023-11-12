package types

import "time"

type Config struct {
	ShutdownTimeout time.Duration

	GitHubClientID     string
	GitHubClientSecret string

	DBConnectionURL string
}
