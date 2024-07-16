package handlers

import (
	"net/http"

	"github.com/rarimo/geo-auth-svc/internal/jwt"
	"gitlab.com/distributed_lab/ape"
	"gitlab.com/distributed_lab/ape/problems"
)

func Refresh(w http.ResponseWriter, r *http.Request) {
	claim := Claim(r)
	if claim == nil {
		ape.RenderErr(w, problems.Unauthorized())
		return
	}

	if claim.Type != jwt.RefreshTokenType {
		ape.RenderErr(w, problems.Unauthorized())
		return
	}

	access, refresh, aexp, rexp, err := issueJWTs(r, claim.Nullifier, claim.SharedHash, claim.IsVerified)
	if err != nil {
		Log(r).WithError(err).WithField("user", claim.Nullifier).Error("failed to issue JWTs")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	Cookies(r).SetAccessToken(w, access, aexp)
	Cookies(r).SetRefreshToken(w, refresh, rexp)
	ape.Render(w, newTokenResponse(claim.Nullifier, access, refresh))
}
