package handlers

import (
	"net/http"

	"github.com/rarimo/geo-auth-svc/internal/jwt"
	"github.com/rarimo/geo-auth-svc/internal/service/requests"
	"gitlab.com/distributed_lab/ape"
	"gitlab.com/distributed_lab/ape/problems"
)

func AuthorizeAdmin(w http.ResponseWriter, r *http.Request) {
	req, err := requests.NewAuthorizeAdminRequest(r)
	if err != nil {
		Log(r).WithError(err).Debug("failed to parse request")
		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	if !Points(r).Disabled && !Points(r).VerifyAdmin(req.Data.Attributes.Password) {
		ape.RenderErr(w, problems.Unauthorized())
		return
	}

	access, aexp, err := JWT(r).IssueJWT(
		&jwt.AuthClaim{
			Nullifier:  "",
			Type:       jwt.AccessTokenType,
			IsVerified: false,
			IsAdmin:    true,
		},
	)
	if err != nil {
		Log(r).WithError(err).Error("failed to issue JWT access token")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	Cookies(r).SetAccessToken(w, access, aexp)
	ape.Render(w, newTokenResponse(req.Data.ID, access, ""))
}
