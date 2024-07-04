package service

import (
	"github.com/go-chi/chi"
	"github.com/rarimo/geo-auth-svc/internal/data/pg"
	"github.com/rarimo/geo-auth-svc/internal/jwt"
	"github.com/rarimo/geo-auth-svc/internal/service/handlers"
	"github.com/rarimo/geo-auth-svc/internal/service/middleware"
	"gitlab.com/distributed_lab/ape"
)

func (s *service) router() chi.Router {
	r := chi.NewRouter()

	r.Use(
		ape.RecoverMiddleware(s.log),
		ape.LoganMiddleware(s.log),
		ape.CtxMiddleware(
			handlers.CtxLog(s.log),
			handlers.CtxJWT(s.jwt),
			handlers.CtxAuthVerifier(s.authVerifier),
			handlers.CtxPassportVerifier(s.passportVerifier),
			handlers.CtxSigVerifier(s.sigVerifier),
			handlers.CtxCookies(s.cookies),
			handlers.CtxUsersQ(pg.NewUsersQ(s.db.Clone())),
			handlers.CtxPoints(s.points),
		),
	)

	r.Route("/integrations/geo-auth-svc", func(r chi.Router) {
		r.Route("/v2", func(r chi.Router) {
			r.Post("/authorize", handlers.AuthorizeV2)
			r.With(middleware.AuthMiddleware(s.jwt, s.log, jwt.AccessTokenType)).Post("/verifypassport", handlers.VerifyPassport)
			r.With(middleware.AuthMiddleware(s.jwt, s.log, jwt.AccessTokenType)).Post("/joinprogram", handlers.JoinProgram)
		})
		r.Route("/v1", func(r chi.Router) {
			r.Route("/authorize", func(r chi.Router) {
				r.Post("/admin", handlers.AuthorizeAdmin)
				r.Post("/", handlers.Authorize)
				r.Get("/{nullifier}/challenge", handlers.RequestChallenge)
			})
			r.With(middleware.AuthMiddleware(s.jwt, s.log, jwt.AccessTokenType)).Get("/validate", handlers.Validate)
			r.With(middleware.AuthMiddleware(s.jwt, s.log, jwt.RefreshTokenType)).Get("/refresh", handlers.Refresh)
		})
	})

	return r
}
