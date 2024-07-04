package requests

import (
	"encoding/json"
	"net/http"
	"strings"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/rarimo/geo-auth-svc/internal/zkp"
	"github.com/rarimo/geo-auth-svc/resources"
)

func NewJoinProgram(r *http.Request) (req resources.JoinProgramRequest, err error) {
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
			validation.In(resources.JOIN_PROGRAM)),
		"data/attributes/anonymous_id": validation.Validate(req.Data.Attributes.AnonymousId, validation.Required, validation.Match(zkp.AIDRegexp)),
	}.Filter()
}
