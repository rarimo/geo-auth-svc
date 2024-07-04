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

func NewVerifyPassport(r *http.Request) (req resources.VerifyPassportRequest, err error) {
	if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
		return req, newDecodeError("body", err)
	}

	req.Data.ID = strings.ToLower(req.Data.ID)

	return req, validation.Errors{
		"data/id": validation.Validate(req.Data.ID,
			validation.Required,
			validation.Match(zkp.NullifierRegexp)),
		"data/type": validation.Validate(req.Data.Type,
			validation.Required,
			validation.In(resources.VERIFY_PASSPORT)),
		"data/attributes/proof/pub_signals/nullifier": validation.Validate(req.Data.ID, validation.In(mustHexFromDecString(req.Data.Attributes.Proof.PubSignals[zk.Nullifier]))),
		"data/attributes/anonymous_id":                validation.Validate(req.Data.Attributes.AnonymousId, validation.Required, validation.Match(zkp.AIDRegexp)),
		"data/attributes/proof/proof":                 validation.Validate(req.Data.Attributes.Proof.Proof, validation.Required),
		"data/attributes/proof/pub_signals":           validation.Validate(req.Data.Attributes.Proof.PubSignals, validation.Required, validation.Length(22, 22)),
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
		return "0"
	}

	return strings.ToLower("0x" + bigDec.Text(16))
}
