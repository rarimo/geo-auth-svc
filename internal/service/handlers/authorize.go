package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	zkptypes "github.com/iden3/go-rapidsnark/types"
	"github.com/rarimo/geo-auth-svc/internal/jwt"
	"github.com/rarimo/geo-auth-svc/internal/service/requests"
	"github.com/rarimo/geo-auth-svc/resources"
	"gitlab.com/distributed_lab/ape"
	"gitlab.com/distributed_lab/ape/problems"
)

func Authorize(w http.ResponseWriter, r *http.Request) {
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

	verified := Points(r).DefaultVerified

	if !Points(r).Disabled {
		verified, err = findOutVerificationStatus(r, req)
		if err != nil {
			Log(r).WithError(err).Warnf("failed to find out passport verification status for [%s]; IsVerified set to false", req.Data.ID)
		}
	}

	access, refresh, aexp, rexp, err := issueJWTs(r, req.Data.ID, verified)
	if err != nil {
		Log(r).WithError(err).WithField("user", req.Data.ID).Error("failed to issue JWTs")
		ape.RenderErr(w, problems.InternalError())
		return
	}

	Cookies(r).SetAccessToken(w, access, aexp)
	Cookies(r).SetRefreshToken(w, refresh, rexp)
	ape.Render(w, newTokenResponse(req.Data.ID, access, refresh))
}

func findOutVerificationStatus(r *http.Request, req *resources.AuthorizeRequest) (bool, error) {
	reqV, err := http.NewRequest("GET", Points(r).URL+Points(r).Endpoint+req.Data.ID, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create GET request: %w", err)
	}

	access, _, err := JWT(r).IssueJWT(&jwt.AuthClaim{
		Nullifier: req.Data.ID,
		Type:      jwt.AccessTokenType,
	})
	if err != nil {
		return false, fmt.Errorf("failed to issueJWT: %w", err)
	}

	cookies, err := cookiejar.New(nil)
	if err != nil {
		return false, fmt.Errorf("failed to create cookiejar: %w", err)
	}

	client := &http.Client{
		Jar:     cookies,
		Timeout: 5 * time.Second,
	}

	client.Jar.SetCookies(reqV.URL, []*http.Cookie{{
		Name:  jwt.AccessTokenType.String(),
		Value: access,
	}})

	resp, err := client.Do(reqV)
	if err != nil {
		return false, fmt.Errorf("failed to perform request: %w", err)
	}
	defer func() { resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read resp body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("api error with status code %d %s", resp.StatusCode, respBody)
	}

	var result BalanceResponse
	err = json.Unmarshal(respBody, &result)
	if err != nil {
		return false, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return result.Data.Attributes.IsVerified, nil
}

type BalanceResponse struct {
	Data struct {
		Attributes struct {
			IsVerified bool `json:"is_verified"`
		} `json:"attributes"`
	} `json:"data"`
}
