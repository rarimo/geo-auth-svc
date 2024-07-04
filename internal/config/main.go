package config

import (
	"github.com/rarimo/geo-auth-svc/internal/cookies"
	"github.com/rarimo/geo-auth-svc/internal/jwt"
	"github.com/rarimo/geo-auth-svc/internal/zkp"
	zk "github.com/rarimo/zkverifier-kit"
	"github.com/rarimo/zkverifier-kit/identity"
	"gitlab.com/distributed_lab/kit/comfig"
	"gitlab.com/distributed_lab/kit/kv"
	"gitlab.com/distributed_lab/kit/pgdb"
)

type Config interface {
	comfig.Logger
	comfig.Listenerer
	pgdb.Databaser

	jwt.Jwter
	zkp.AuthVerifierer
	cookies.Cookier

	Points() *Points
	PassportVerifier() *zk.Verifier
	SigVerifier() []byte
}

type config struct {
	comfig.Logger
	comfig.Listenerer
	pgdb.Databaser

	identity.VerifierProvider

	jwt.Jwter
	zkp.AuthVerifierer
	cookies.Cookier

	points           comfig.Once
	passportVerifier comfig.Once
	sigVerifier      comfig.Once
	getter           kv.Getter
}

func New(getter kv.Getter) Config {
	return &config{
		getter:           getter,
		Databaser:        pgdb.NewDatabaser(getter),
		Listenerer:       comfig.NewListenerer(getter),
		Logger:           comfig.NewLogger(getter, comfig.LoggerOpts{}),
		Jwter:            jwt.NewJwter(getter),
		AuthVerifierer:   zkp.NewAuthVerifierer(getter),
		VerifierProvider: identity.NewVerifierProvider(getter),
		Cookier:          cookies.NewCookier(getter),
	}
}
