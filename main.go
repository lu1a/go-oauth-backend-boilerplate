package main

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/charmbracelet/log"
	"github.com/joho/godotenv"
	"github.com/lu1a/go-oauth-backend-boilerplate/service"
	"github.com/lu1a/go-oauth-backend-boilerplate/types"
)

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Did you create and fill a '.env' file?", "err", err)
	}

	shutdownTimeout, err := time.ParseDuration(os.Getenv("SHUTDOWN_TIMEOUT"))
	if err != nil {
		log.Fatal("Pls set the shutdown timeout correctly", "err", err)
	}

	config := types.Config{
		ShutdownTimeout: shutdownTimeout,

		GitHubClientID:     os.Getenv("GITHUB_OAUTH_CLIENT_ID"),
		GitHubClientSecret: os.Getenv("GITHUB_OAUTH_CLIENT_SECRET"),

		DBConnectionURL: os.Getenv("DB_CONNECTION_URL"),
	}

	err = runService(config)
	if err != nil {
		log.Fatal("Service failed to start normally", "err", err)
	}
}

func runService(config types.Config) error {
	chInterrupt := make(chan os.Signal, 1)
	chService := make(chan *service.Service)
	log := log.New(os.Stdout)

	var s = service.New(config, *log)

	closeCtx, err := s.Start()
	if err != nil {
		log.Error("service start", "error", err)
		os.Exit(1)
	}
	s.CloseNotify(closeCtx, chService)
	signal.Notify(chInterrupt, os.Interrupt, syscall.SIGTERM)
	select {
	case <-chInterrupt:
		log.Info("received SIGTERM, shutting down")
		if err = s.Close(); err != nil {
			log.Error("close service", "error", err)
			os.Exit(1)
		}
	case <-chService:
		if err = s.CloseError(); err != nil {
			log.Error("close service", "error", err)
			os.Exit(1)
		}
	}
	log.Info("Shutdown complete")
	return nil
}
