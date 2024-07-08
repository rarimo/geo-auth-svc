package service

import (
	"net"
	"net/http"

	"github.com/rarimo/geo-auth-svc/internal/config"
	"github.com/rarimo/geo-auth-svc/internal/cookies"
	"github.com/rarimo/geo-auth-svc/internal/jwt"
	"github.com/rarimo/geo-auth-svc/internal/zkp"
	zk "github.com/rarimo/zkverifier-kit"
	"gitlab.com/distributed_lab/logan/v3"
)

type service struct {
	log              *logan.Entry
	listener         net.Listener
	jwt              *jwt.JWTIssuer
	authVerifier     *zkp.AuthVerifier
	passportVerifier *zk.Verifier
	cookies          *cookies.Cookies
	points           *config.Points
}

func (s *service) run() error {
	s.log.Info("Service started")
	r := s.router()
	return http.Serve(s.listener, r)
}

func newService(cfg config.Config) *service {
	return &service{
		log:              cfg.Log(),
		listener:         cfg.Listener(),
		jwt:              cfg.JWT(),
		authVerifier:     cfg.AuthVerifier(),
		passportVerifier: cfg.PassportVerifier(),
		cookies:          cfg.Cookies(),
		points:           cfg.Points(),
	}
}

func Run(cfg config.Config) {
	if err := newService(cfg).run(); err != nil {
		panic(err)
	}
}
