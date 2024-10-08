package zkp

import (
	"errors"
	"regexp"
	"time"
)

// https://github.com/iden3/circuits/blob/master/circuits/authV2.circom
//
// Proof pub signals example with description:
//
// 21493028867609342730075626961959697053940727668683389257942040837777854978 - user did (index 0)
// 21493028867609342730075626961959697053940727668683389257942040837777854978 - challenge (index 1)
// 16285847858933578151298306208524779888950768974039235725833670860163361043104 - gistRoot (index 2)
const (
	NullifierSignalsIndex      = 0
	PkIdentityHashSignalsIndex = 1
	EventIDSignalsIndex        = 2
	EventDataSignalsIndex      = 3
)

const ChallengeExpirationDelta = 5 * time.Minute

const EventIDValue = "111186066134341633902189494613533900917417361106374681011849132651019822199"

var NullifierRegexp = regexp.MustCompile("^0x[0-9a-fA-F]{64}$")

type Challenge struct {
	Value    string
	Exp      time.Time
	Verified bool
}

var (
	ErrChallengeWasNotRequested = errors.New("challenge was not requested")
	ErrChallengeIsInvalid       = errors.New("challenge is already invalid")
)
