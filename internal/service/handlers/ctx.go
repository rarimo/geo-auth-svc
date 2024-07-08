package handlers

import (
	"context"
	"net/http"

	"github.com/rarimo/geo-auth-svc/internal/config"
	"github.com/rarimo/geo-auth-svc/internal/cookies"
	"github.com/rarimo/geo-auth-svc/internal/jwt"
	"github.com/rarimo/geo-auth-svc/internal/zkp"
	zk "github.com/rarimo/zkverifier-kit"
	"gitlab.com/distributed_lab/logan/v3"
)

type ctxKey int

const (
	logCtxKey ctxKey = iota
	jwtKey
	claimKey
	authVerifierKey
	passportVerifierKey
	cookiesKey
	usersQKey
	sigCalculatorKey
	pointsKey
)

func CtxLog(entry *logan.Entry) func(context.Context) context.Context {
	return func(ctx context.Context) context.Context {
		return context.WithValue(ctx, logCtxKey, entry)
	}
}

func CtxJWT(issuer *jwt.JWTIssuer) func(context.Context) context.Context {
	return func(ctx context.Context) context.Context {
		return context.WithValue(ctx, jwtKey, issuer)
	}
}

func CtxClaim(claim *jwt.AuthClaim) func(context.Context) context.Context {
	return func(ctx context.Context) context.Context {
		return context.WithValue(ctx, claimKey, claim)
	}
}

func CtxAuthVerifier(verifier *zkp.AuthVerifier) func(context.Context) context.Context {
	return func(ctx context.Context) context.Context {
		return context.WithValue(ctx, authVerifierKey, verifier)
	}
}

func CtxPassportVerifier(verifier *zk.Verifier) func(context.Context) context.Context {
	return func(ctx context.Context) context.Context {
		return context.WithValue(ctx, passportVerifierKey, verifier)
	}
}

func CtxCookies(cookies *cookies.Cookies) func(context.Context) context.Context {
	return func(ctx context.Context) context.Context {
		return context.WithValue(ctx, cookiesKey, cookies)
	}
}

func CtxPoints(points *config.Points) func(context.Context) context.Context {
	return func(ctx context.Context) context.Context {
		return context.WithValue(ctx, pointsKey, points)
	}
}

func Log(r *http.Request) *logan.Entry {
	return r.Context().Value(logCtxKey).(*logan.Entry)
}

func JWT(r *http.Request) *jwt.JWTIssuer {
	return r.Context().Value(jwtKey).(*jwt.JWTIssuer)
}

func Claim(r *http.Request) *jwt.AuthClaim {
	return r.Context().Value(claimKey).(*jwt.AuthClaim)
}

func AuthVerifier(r *http.Request) *zkp.AuthVerifier {
	return r.Context().Value(authVerifierKey).(*zkp.AuthVerifier)
}

func PassportVerifier(r *http.Request) *zk.Verifier {
	return r.Context().Value(passportVerifierKey).(*zk.Verifier)
}

func Cookies(r *http.Request) *cookies.Cookies {
	return r.Context().Value(cookiesKey).(*cookies.Cookies)
}

func Points(r *http.Request) *config.Points {
	return r.Context().Value(pointsKey).(*config.Points)
}
