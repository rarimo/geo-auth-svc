package auth

import (
	"github.com/rarimo/geo-auth-svc/resources"
)

func UserGrant(nullifier string) Grant {
	return func(claim resources.Claim) bool {
		return claim.Nullifier == nullifier
	}
}

func VerifiedGrant(nullifier string) Grant {
	return func(claim resources.Claim) bool {
		return claim.Nullifier == nullifier && claim.IsVerified
	}
}
