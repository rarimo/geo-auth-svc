package handlers

import (
	"errors"
	"math/big"
	"net/http"

	"github.com/ethereum/go-ethereum/common/hexutil"
	zk "github.com/rarimo/zkverifier-kit"
	"github.com/rarimo/zkverifier-kit/identity"

	"github.com/rarimo/geo-auth-svc/internal/service/requests"
	"gitlab.com/distributed_lab/ape"
	"gitlab.com/distributed_lab/ape/problems"
)

func AuthorizeV2(w http.ResponseWriter, r *http.Request) {
	req, err := requests.NewAuthorizeV2(r)
	if err != nil {
		Log(r).WithError(err).Debug("Bad request")
		ape.RenderErr(w, problems.BadRequest(err)...)
		return
	}

	nullifier := req.Data.ID
	proof := req.Data.Attributes.Proof

	// never panics because of request validation
	ni := zk.Indexes(zk.GeorgianPassport)[zk.Nullifier]
	proof.PubSignals[ni] = mustHexToInt(nullifier)
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
