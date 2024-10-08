package handlers

import (
	"net/http"

	"github.com/rarimo/geo-auth-svc/internal/jwt"
	"github.com/rarimo/geo-auth-svc/resources"
	"gitlab.com/distributed_lab/ape"
	"gitlab.com/distributed_lab/ape/problems"
)

func Validate(w http.ResponseWriter, r *http.Request) {
	claim := Claim(r)
	if claim == nil {
		ape.RenderErr(w, problems.Unauthorized())
		return
	}

	if claim.Type != jwt.AccessTokenType {
		ape.RenderErr(w, problems.Unauthorized())
		return
	}

	resp := resources.ValidationResultResponse{
		Data: resources.ValidationResult{
			Key: resources.Key{
				ID:   claim.Nullifier,
				Type: resources.VALIDATION,
			},
			Attributes: resources.ValidationResultAttributes{
				Claims: []resources.Claim{
					{
						Nullifier:  claim.Nullifier,
						IsVerified: claim.IsVerified,
						IsAdmin:    claim.IsAdmin,
						SharedHash: claim.SharedHash,
					},
				},
			},
		},
	}

	ape.Render(w, resp)
}
