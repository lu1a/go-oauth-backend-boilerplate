package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path"
	"sync"
	"text/template"
	"time"

	_ "github.com/lib/pq"

	"github.com/charmbracelet/log"
	"github.com/go-chi/chi/v5"
	"github.com/jmoiron/sqlx"
	"github.com/lu1a/go-oauth-backend-boilerplate/api"
	middleware "github.com/lu1a/go-oauth-backend-boilerplate/middleware/auth"
	"github.com/lu1a/go-oauth-backend-boilerplate/types"
)

type Service struct {
	config            types.Config
	log               log.Logger
	wg                sync.WaitGroup
	serviceMutex      sync.Mutex
	closeDependencies func()
	closeErr          error

	db  *sqlx.DB
	API *http.Server
}

func New(config types.Config, log log.Logger) *Service {
	return &Service{
		config: config,
		log:    log,
	}
}

func (s *Service) Start() (context.Context, error) {
	var closeCtx context.Context
	closeCtx, s.closeDependencies = context.WithCancel(context.Background())

	startError := func(err error) error {
		s.closeDependencies()
		s.closeErr = err
		return err
	}

	if err := s.initDatabase(); err != nil {
		return nil, startError(err)
	}
	if err := s.startAPI(); err != nil {
		return nil, startError(err)
	}

	return closeCtx, nil
}

func (s *Service) initDatabase() (err error) {
	s.db, err = sqlx.Connect("postgres", s.config.DBConnectionURL)
	if err != nil {
		return err
	}
	return nil
}

func (s *Service) startAPI() (err error) {
	log.Info("Starting server..")

	r := chi.NewRouter()

	mw := middleware.AuthMiddleware(http.DefaultServeMux, s.db)
	r.Use(mw)

	r.Route("/api", api.APIRouter(s.log, s.db, s.config, r))

	r.Get("/login", func(w http.ResponseWriter, r *http.Request) {
		fp := path.Join("templates", "login.html")
		tmpl, err := template.ParseFiles(fp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if err := tmpl.Execute(w, struct{}{}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		fp := path.Join("templates", "index.html")
		tmpl, err := template.ParseFiles(fp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if err := tmpl.Execute(w, struct{}{}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	if s.API, err = s.initHTTPServer(r); err != nil {
		return err
	}
	return nil
}

func (s *Service) initHTTPServer(r *chi.Mux) (*http.Server, error) {
	l, err := net.Listen("tcp", "localhost:8080")
	if err != nil {
		return nil, fmt.Errorf("create tcp listener: %w", err)
	}

	serv := &http.Server{
		Addr:    "localhost:8080",
		Handler: r,
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		err = serv.Serve(l)
		if !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("API start", "error", err)
			s.setCloseError(err)
			if err = s.Close(); err != nil {
				s.log.Error("API close", "error", err)
			}
		}
	}()
	return serv, nil
}

func (s *Service) Close() error {
	s.serviceMutex.Lock()
	defer s.serviceMutex.Unlock()

	chDone := make(chan struct{})
	timeout := time.After(s.config.ShutdownTimeout)
	ctx, cancel := context.WithTimeout(context.Background(), s.config.ShutdownTimeout)

	go func() {
		defer close(chDone)
		defer cancel()

		if s.API != nil {
			s.log.Info("Closing API")
			if err := s.API.Shutdown(ctx); err != nil {
				s.log.Error("error closing API", "error", err)
			}
			s.API = nil
		}

		if s.db != nil {
			s.log.Info("Closing DB connection")
			s.db.Close()
			s.db = nil
		}

		s.closeDependencies()

		s.log.Info("Waiting for Service workers to finish")
		s.wg.Wait()
	}()

	select {
	case <-chDone:
		return s.closeErr
	case <-timeout:
		s.closeErr = errors.New("Timed out while waiting for dependencies to close")
		return s.closeErr
	}
}

// CloseNotify sends self to notify channel when the service has been closed.
func (s *Service) CloseNotify(ctx context.Context, chNotify chan<- *Service) {
	go func() {
		<-ctx.Done()
		chNotify <- s
	}()
}

func (s *Service) setCloseError(err error) {
	s.serviceMutex.Lock()
	defer s.serviceMutex.Unlock()

	s.closeErr = err
}

// CloseError is an accessor for retrieving a close error.
func (s *Service) CloseError() error {
	s.serviceMutex.Lock()
	defer s.serviceMutex.Unlock()
	return s.closeErr
}
