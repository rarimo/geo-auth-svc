package handlers

import (
	"net/http"

	"github.com/rarimo/geo-auth-svc/internal/data"
	"github.com/rarimo/geo-auth-svc/internal/jwt"
	"github.com/rarimo/geo-auth-svc/internal/service/requests"
	"gitlab.com/distributed_lab/ape"
	"gitlab.com/distributed_lab/ape/problems"
)

func JoinProgram(w http.ResponseWriter, r *http.Request) {
	req, err := requests.NewJoinProgram(r)
	if err != nil {
		Log(r).WithError(err).Debug("Bad request")
		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	log := Log(r).WithFields(map[string]any{
		"user.nullifier":    req.Data.ID,
		"user.anonymous_id": req.Data.Attributes.AnonymousId,
	})

	nullifier := req.Data.ID
	anonymousID := req.Data.Attributes.AnonymousId

	claim := Claim(r)
	if claim == nil || claim.Type != jwt.AccessTokenType || claim.Nullifier != nullifier {
		ape.RenderErr(w, problems.Unauthorized())
		return
	}

	gotSig := r.Header.Get("Signature")
	wantSig, err := SigCalculator(r).PassportVerificationSignature(req.Data.ID, anonymousID)
	if err != nil { // must never happen due to preceding validation
		Log(r).WithError(err).Error("Failed to calculate HMAC signature")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	if gotSig != wantSig {
		log.Warnf("Passport verification unauthorized access: HMAC signature mismatch: got %s, want %s", gotSig, wantSig)
		ape.RenderErr(w, problems.Forbidden())
		return
	}

	byNullifier, err := UsersQ(r).FilterByNullifier(nullifier).Get()
	if err != nil {
		log.WithError(err).Error("Failed to get user by nullifier")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	if byNullifier != nil {
		log.Warnf("User %s already verified", nullifier)
		ape.RenderErr(w, problems.TooManyRequests())
		return
	}

	byAnonymousID, err := UsersQ(r).FilterByAnonymousID(anonymousID).Get()
	if err != nil {
		log.WithError(err).Error("Failed to get user by anonymous ID")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	if byAnonymousID != nil {
		log.Warnf("Anonymous ID already used by another user: nullifier=%s, AID=%s", nullifier, anonymousID)
		ape.RenderErr(w, problems.Conflict())
		return
	}

	err = UsersQ(r).Insert(data.User{
		Nullifier:   nullifier,
		AnonymousID: anonymousID,
		IsProven:    false,
	})
	if err != nil {
		Log(r).WithError(err).Error("failed to insert user")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	access, refresh, aexp, rexp, err := issueJWTs(r, req.Data.ID, true)
	if err != nil {
		Log(r).WithError(err).WithField("user", req.Data.ID).Error("failed to issue JWTs")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	Cookies(r).SetAccessToken(w, access, aexp)
	Cookies(r).SetRefreshToken(w, refresh, rexp)
	ape.Render(w, newTokenResponse(req.Data.ID, access, refresh))
}
