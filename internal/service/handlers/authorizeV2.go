package handlers

import (
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	zkptypes "github.com/iden3/go-rapidsnark/types"
	"github.com/rarimo/geo-auth-svc/internal/jwt"
	"github.com/rarimo/geo-auth-svc/internal/service/requests"
	"github.com/rarimo/geo-auth-svc/resources"
	"gitlab.com/distributed_lab/ape"
	"gitlab.com/distributed_lab/ape/problems"
)

func AuthorizeV2(w http.ResponseWriter, r *http.Request) {
	req, err := requests.NewAuthorizeRequest(r)
	if err != nil {
		Log(r).WithError(err).Debug("failed to parse request")
		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	if !AuthVerifier(r).Disabled {
		var proof zkptypes.ZKProof
		if err := json.Unmarshal(req.Data.Attributes.Proof, &proof); err != nil {
			ape.RenderErr(w, problems.BadRequest(err)...)
			return
		}

		nullifier, err := hexutil.Decode(req.Data.ID)
		if err != nil {
			ape.RenderErr(w, problems.BadRequest(err)...)
			return
		}

		if err = AuthVerifier(r).VerifyProof(new(big.Int).SetBytes(nullifier).String(), &proof); err != nil {
			Log(r).WithError(err).Info("Failed to verify proof")
			ape.RenderErr(w, problems.Unauthorized())
			return
		}
	}

	user, err := UsersQ(r).FilterByNullifier(req.Data.ID).Get()
	if err != nil {
		Log(r).WithError(err).WithField("user", req.Data.ID).Error("failed to get user")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	access, refresh, aexp, rexp, err := issueJWTs(r, req.Data.ID, user != nil)
	if err != nil {
		Log(r).WithError(err).WithField("user", req.Data.ID).Error("failed to issue JWTs")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	Cookies(r).SetAccessToken(w, access, aexp)
	Cookies(r).SetRefreshToken(w, refresh, rexp)
	ape.Render(w, newTokenResponse(req.Data.ID, access, refresh))
}

func newTokenResponse(nullifier, access, refresh string) resources.TokenResponse {
	return resources.TokenResponse{
		Data: resources.Token{
			Key: resources.Key{
				ID:   nullifier,
				Type: resources.TOKEN,
			},
			Attributes: resources.TokenAttributes{
				AccessToken: resources.Jwt{
					Token:     access,
					TokenType: string(jwt.AccessTokenType),
				},
				RefreshToken: resources.Jwt{
					Token:     refresh,
					TokenType: string(jwt.RefreshTokenType),
				},
			},
		},
	}
}

func issueJWTs(r *http.Request, nullifier string, verified bool) (access, refresh string, aexp, rexp time.Time, err error) {
	access, aexp, err = JWT(r).IssueJWT(
		&jwt.AuthClaim{
			Nullifier:  nullifier,
			Type:       jwt.AccessTokenType,
			IsVerified: verified,
		},
	)
	if err != nil {
		return "", "", aexp, rexp, fmt.Errorf("failed to issue JWT access token: %w", err)
	}

	refresh, rexp, err = JWT(r).IssueJWT(
		&jwt.AuthClaim{
			Nullifier:  nullifier,
			Type:       jwt.RefreshTokenType,
			IsVerified: verified,
		},
	)
	if err != nil {
		return "", "", aexp, rexp, fmt.Errorf("failed to issue JWT access token: %w", err)
	}

	return access, refresh, aexp, rexp, nil
}
