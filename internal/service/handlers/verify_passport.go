package handlers

import (
	"errors"
	"math/big"
	"net/http"

	"github.com/ethereum/go-ethereum/common/hexutil"
	zk "github.com/rarimo/zkverifier-kit"
	"github.com/rarimo/zkverifier-kit/identity"

	"github.com/rarimo/geo-auth-svc/internal/data"
	"github.com/rarimo/geo-auth-svc/internal/jwt"
	"github.com/rarimo/geo-auth-svc/internal/service/requests"
	"gitlab.com/distributed_lab/ape"
	"gitlab.com/distributed_lab/ape/problems"
)

func VerifyPassport(w http.ResponseWriter, r *http.Request) {
	req, err := requests.NewVerifyPassport(r)
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
	proof := req.Data.Attributes.Proof

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

	if byNullifier != nil && byNullifier.IsProven {
		log.Warnf("User %s already proven", nullifier)
		ape.RenderErr(w, problems.TooManyRequests())
		return
	}

	byAnonymousID, err := UsersQ(r).FilterByAnonymousID(anonymousID).Get()
	if err != nil {
		log.WithError(err).Error("Failed to get user by anonymous ID")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	if reason := validateScanAbility(byNullifier, byAnonymousID); reason != "" {
		log.WithFields(map[string]interface{}{
			"nullifier": nullifier,
			"AID":       anonymousID,
		}).Warn(reason)
		ape.RenderErr(w, problems.Conflict())
		return
	}

	// never panics because of request validation
	proof.PubSignals[zk.Nullifier] = mustHexToInt(nullifier)
	err = PassportVerifier(r).VerifyProof(proof)
	if err != nil {
		if errors.Is(err, identity.ErrContractCall) {
			Log(r).WithError(err).Error("failed to verify proof")
			ape.RenderErr(w, problems.InternalError())
			return
		}

		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	if byNullifier != nil {
		if err = UsersQ(r).FilterByNullifier(nullifier).UpdateIsProven(true); err != nil {
			Log(r).WithError(err).Error("failed to update user")
			ape.RenderErr(w, problems.InternalError())
			return
		}
	} else {
		err = UsersQ(r).Insert(data.User{
			Nullifier:   nullifier,
			AnonymousID: anonymousID,
			IsProven:    true,
		})
		if err != nil {
			Log(r).WithError(err).Error("failed to insert user")
			ape.RenderErr(w, problems.InternalError())
			return
		}
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

func mustHexToInt(s string) string {
	return new(big.Int).SetBytes(hexutil.MustDecode(s)).String()
}

func validateScanAbility(byNull, byAID *data.User) (reason string) {
	switch {
	case byNull == nil && byAID != nil:
		return "byAnonymousID present, while byNullifier absent"
	case byNull != nil && byAID == nil:
		return "byNullifier present, while byAnonymousID absent"
	case byNull != nil && byAID != nil && byNull.Nullifier != byAID.Nullifier:
		return "byAnonymousID and byNullifier must point to the same record"
	}
	return ""
}
