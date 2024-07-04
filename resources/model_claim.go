/*
 * GENERATED. Do not modify. Your changes might be overwritten!
 */

package resources

// Authorized user personal data
type Claim struct {
	// Whether the user has a scanned passport
	IsVerified bool `json:"is_verified"`
	// Nullifier authorized with
	Nullifier string `json:"nullifier"`
}
