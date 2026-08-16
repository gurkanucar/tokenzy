// Package token owns everything that makes a token a token: how one is
// generated, how its status is derived, and what inputs are accepted when one
// is issued. The SQL that stores and spends tokens lives in package db.
package token

import (
	"encoding/hex"
	"fmt"

	"github.com/google/uuid"
)

const (
	// ValuePrefix marks a token so a leaked string is recognisable for what it
	// is — worth grepping logs for, and worth a secret scanner matching on.
	ValuePrefix = "tkn_"

	// IDPrefix marks the identifier used by the management API. Deliberately
	// different from ValuePrefix: an id is not a secret and must never be
	// mistaken for one.
	IDPrefix = "tok_"

	// PrefixLen is how much of a token is stored separately for display. Twelve
	// characters is "tkn_" plus eight hex digits — enough to tell two rows
	// apart in a listing, far too little to be worth guessing the rest from.
	PrefixLen = 12
)

// Generate returns a fresh token: "tkn_" followed by 64 hex characters.
//
// The 32 bytes come from two random (version 4) UUIDs laid end to end. Six of
// those bits are spent on the UUID version and variant markers, which leaves
// ~244 bits of randomness. That number is the reason this service has no
// attempt counter, no cooldown and no rate limit on /v1/consume: guessing is
// not a threat that arithmetic leaves on the table, so defending against it
// would be theatre. What is left to defend against is a token that leaks, and
// no counter helps with that — short TTLs and revocation do.
func Generate() (string, error) {
	first, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	second, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}

	var raw [32]byte
	copy(raw[:16], first[:])
	copy(raw[16:], second[:])
	return ValuePrefix + hex.EncodeToString(raw[:]), nil
}

// NewID returns an identifier for a token row: "tok_" and 32 hex characters.
func NewID() (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("generate token id: %w", err)
	}
	return IDPrefix + hex.EncodeToString(id[:]), nil
}

// Prefix returns the leading characters of a token, which is all that listings
// and webhook payloads are ever allowed to carry.
func Prefix(value string) string {
	if len(value) <= PrefixLen {
		return value
	}
	return value[:PrefixLen]
}

// Mask renders a token safe to write down — in a log line, an error message,
// anywhere at all. Nothing in this service logs a token today; this exists so
// that when something is tempted to, there is an obvious right way to do it.
func Mask(value string) string {
	if value == "" {
		return ""
	}
	return Prefix(value) + "…"
}
