package jwt

import (
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

const (
	NullifierClaimName           = "sub"
	ExpirationTimestampClaimName = "exp"
	TokenTypeClaimName           = "type"
	IsVerifiedClaimName          = "verified"
	IsAdminClaimName             = "admin"
	SharedHashName               = "shared"
)

type TokenType string

func (t TokenType) String() string {
	return string(t)
}

var (
	AccessTokenType  TokenType = "access"
	RefreshTokenType TokenType = "refresh"
)

// AuthClaim is a helper structure to organize all claims in one entity
type AuthClaim struct {
	Nullifier  string
	Type       TokenType
	IsVerified bool
	IsAdmin    bool
	SharedHash string
}

// RawJWT represents helper structure to provide setter and getter methods to work with JWT claims
type RawJWT struct {
	claims jwt.MapClaims
}

// Setters

func (r *RawJWT) SetNullifier(nullifier string) *RawJWT {
	r.claims[NullifierClaimName] = nullifier
	return r
}

func (r *RawJWT) SetExpirationTimestamp(expiration time.Time) *RawJWT {
	r.claims[ExpirationTimestampClaimName] = jwt.NewNumericDate(expiration)
	return r
}

func (r *RawJWT) SetIsVerified(isVerified bool) *RawJWT {
	r.claims[IsVerifiedClaimName] = isVerified
	return r
}

func (r *RawJWT) SetIsAdmin(isAdmin bool) *RawJWT {
	r.claims[IsAdminClaimName] = isAdmin
	return r
}

func (r *RawJWT) SetSharedHash(sharedHash string) *RawJWT {
	r.claims[SharedHashName] = sharedHash
	return r
}

func (r *RawJWT) SetTokenAccess() *RawJWT {
	r.claims[TokenTypeClaimName] = AccessTokenType
	return r
}

func (r *RawJWT) SetTokenRefresh() *RawJWT {
	r.claims[TokenTypeClaimName] = RefreshTokenType
	return r
}

// Getters

func (r *RawJWT) Nullifier() (res string, ok bool) {
	var val interface{}

	if val, ok = r.claims[NullifierClaimName]; !ok {
		return
	}

	res, ok = val.(string)
	return
}

func (r *RawJWT) IsVerified() (res bool, ok bool) {
	var val interface{}

	if val, ok = r.claims[IsVerifiedClaimName]; !ok {
		return
	}

	res, ok = val.(bool)
	return
}

func (r *RawJWT) IsAdmin() (res bool, ok bool) {
	var val interface{}

	if val, ok = r.claims[IsAdminClaimName]; !ok {
		return
	}

	res, ok = val.(bool)
	return
}

func (r *RawJWT) SharedHash() (res string, ok bool) {
	var val interface{}

	if val, ok = r.claims[SharedHashName]; !ok {
		return
	}

	res, ok = val.(string)
	return
}

func (r *RawJWT) TokenType() (typ TokenType, ok bool) {
	var (
		val interface{}
		str string
	)

	if val, ok = r.claims[TokenTypeClaimName]; !ok {
		return
	}

	if str, ok = val.(string); !ok {
		return
	}

	return TokenType(str), true
}
