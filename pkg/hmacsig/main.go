package hmacsig

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/google/uuid"
)

type Calculator struct {
	key []byte
}

func NewCalculator(key []byte) Calculator {
	return Calculator{key: key}
}

func (c Calculator) ArbitrarySignature(msg []byte) string {
	h := hmac.New(sha256.New, c.key)
	h.Write(msg)
	return hex.EncodeToString(h.Sum(nil))
}

func (c Calculator) PassportVerificationSignature(nullifier, anonymousID string) (string, error) {
	bNull, err := hex.DecodeString(nullifier[2:])
	if err != nil {
		return "", fmt.Errorf("nullifier is not hex: %w", err)
	}

	bAID, err := hex.DecodeString(anonymousID)
	if err != nil {
		return "", fmt.Errorf("anonymousID is not hex: %w", err)
	}

	msg := append(bNull, bAID...)
	return c.ArbitrarySignature(msg), nil
}

func (c Calculator) QREventSignature(nullifier, eventID, qrCode string) (string, error) {
	bNull, err := hex.DecodeString(nullifier[2:])
	if err != nil {
		return "", fmt.Errorf("nullifier is not hex: %w", err)
	}

	bID, err := uuid.Parse(eventID)
	if err != nil {
		return "", fmt.Errorf("eventID is not uuid: %w", err)
	}

	bQR, err := base64.StdEncoding.DecodeString(qrCode)
	if err != nil {
		return "", fmt.Errorf("qrCode is not base64: %w", err)
	}

	msg := append(bNull, bID[:]...)
	msg = append(msg, bQR...)
	return c.ArbitrarySignature(msg), nil
}
