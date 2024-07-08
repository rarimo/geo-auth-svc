package config

import (
	"github.com/rarimo/geo-auth-svc/internal/cookies"
	"github.com/rarimo/geo-auth-svc/internal/jwt"
	"github.com/rarimo/geo-auth-svc/internal/zkp"
	zk "github.com/rarimo/zkverifier-kit"
	"github.com/rarimo/zkverifier-kit/identity"
	"gitlab.com/distributed_lab/kit/comfig"
	"gitlab.com/distributed_lab/kit/kv"
)

type Config interface {
	comfig.Logger
	comfig.Listenerer

	jwt.Jwter
	zkp.AuthVerifierer
	cookies.Cookier

	Points() *Points
	PassportVerifier() *zk.Verifier
}

type config struct {
	comfig.Logger
	comfig.Listenerer

	identity.VerifierProvider // used internally

	jwt.Jwter
	zkp.AuthVerifierer
	cookies.Cookier

	points           comfig.Once
	passportVerifier comfig.Once
	getter           kv.Getter
}

func New(getter kv.Getter) Config {
	return &config{
		getter:           getter,
		Listenerer:       comfig.NewListenerer(getter),
		Logger:           comfig.NewLogger(getter, comfig.LoggerOpts{}),
		Jwter:            jwt.NewJwter(getter),
		AuthVerifierer:   zkp.NewAuthVerifierer(getter),
		VerifierProvider: identity.NewVerifierProvider(getter),
		Cookier:          cookies.NewCookier(getter),
	}
}
