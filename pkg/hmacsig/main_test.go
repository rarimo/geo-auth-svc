package hmacsig

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCalculator use it to ensure matching signature on re-implementation
func TestCalculator(t *testing.T) {
	var (
		keyString = "ab6b3f7796728e0df9696c4a3eb600b49b51db9d230e94e9c67fef756d695b63"
		key, _    = hex.DecodeString(keyString)
		c         = NewCalculator(key)

		nullifier   = "0x973c253a93e8d2e6022721c6a8bd0205940b50cb478d485ca2cbc3354fae95ec"
		anonymousID = "adeef82557bc0f95c8ffe38eca25e4d1d9da79ea14215ec52b4f21370dd60dbc"

		eventID = "18593155-b6a3-4166-80f1-6bf4c5aeedf1"
		qrCode  = "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAABaElEQVR4AWP4//8/AyUYw000"
	)

	sig, err := c.PassportVerificationSignature(nullifier, anonymousID)
	require.NoError(t, err)
	assert.Equal(t, "f702d802bd77f28486adca12139931c774a224051e21bd409ac3a87ae79b7b7a", sig)

	sig, err = c.QREventSignature(nullifier, eventID, qrCode)
	require.NoError(t, err)
	assert.Equal(t, "490ca1d93d6958a85a9b5be3f79e479ecebc25341d8ad6e905cf74a045bfbf0b", sig)
}
