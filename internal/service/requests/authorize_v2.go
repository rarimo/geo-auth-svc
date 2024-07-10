package requests

import (
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/rarimo/geo-auth-svc/internal/zkp"
	"github.com/rarimo/geo-auth-svc/resources"
	zk "github.com/rarimo/zkverifier-kit"
)

func NewAuthorizeV2(r *http.Request) (req resources.VerifyPassportRequest, err error) {
	if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
		return req, newDecodeError("body", err)
	}

	req.Data.ID = strings.ToLower(req.Data.ID)
	ni := zk.Indexes(zk.GeorgianPassport)[zk.Nullifier]
	nullifier := mustHexFromDecString(req.Data.Attributes.Proof.PubSignals[ni])

	return req, validation.Errors{
		"data/id": validation.Validate(req.Data.ID,
			validation.Required,
			validation.Match(zkp.NullifierRegexp)),
		"data/type": validation.Validate(req.Data.Type,
			validation.Required,
			validation.In(resources.AUTHORIZE_V2)),
		"data/attributes/proof/pub_signals/nullifier": validation.Validate(req.Data.ID, validation.In(nullifier)),
		"data/attributes/proof/proof":                 validation.Validate(req.Data.Attributes.Proof.Proof, validation.Required),
		"data/attributes/proof/pub_signals":           validation.Validate(req.Data.Attributes.Proof.PubSignals, validation.Required, validation.Length(24, 24)),
	}.Filter()
}

func newDecodeError(what string, err error) error {
	return validation.Errors{
		what: fmt.Errorf("decode request %s: %w", what, err),
	}
}

func mustHexFromDecString(dec string) string {
	bigDec, ok := new(big.Int).SetString(dec, 10)
	if !ok {
		return "0x0"
	}

	return strings.ToLower("0x" + bigDec.Text(16))
}
