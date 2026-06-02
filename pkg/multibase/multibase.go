// Package multibase implements the subset of the multibase encoding spec
// (https://github.com/multiformats/multibase) used by tpt-identity: base58btc
// encoding (prefix 'z') for DID key material, and base64url decoding (prefix 'u')
// for backward-compatibility with did:peer and fallback-encoded keys.
package multibase

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

const (
	// base58btcAlphabet is the Bitcoin base58 alphabet used by did:key and did:web.
	base58btcAlphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	prefixBase58BTC   = 'z'
	prefixBase64URL   = 'u'
)

var (
	bigZero  = big.NewInt(0)
	bigBase  = big.NewInt(58)
	alphabet = []byte(base58btcAlphabet)
	// decTable maps base58btc character → value; 255 = invalid.
	decTable [256]byte
)

func init() {
	for i := range decTable {
		decTable[i] = 255
	}
	for i, c := range alphabet {
		decTable[c] = byte(i)
	}
}

// Encode encodes raw bytes as a multibase base58btc string (prefix 'z').
func Encode(raw []byte) string {
	return string(prefixBase58BTC) + encodeBase58BTC(raw)
}

// Decode decodes a multibase-encoded string. Supports base58btc ('z' prefix) and
// base64url ('u' prefix). Returns the raw decoded bytes.
func Decode(s string) ([]byte, error) {
	if len(s) == 0 {
		return nil, errors.New("multibase: empty string")
	}
	switch s[0] {
	case prefixBase58BTC:
		b, err := decodeBase58BTC(s[1:])
		if err != nil {
			return nil, fmt.Errorf("multibase: base58btc: %w", err)
		}
		return b, nil
	case prefixBase64URL:
		b, err := base64.RawURLEncoding.DecodeString(s[1:])
		if err != nil {
			return nil, fmt.Errorf("multibase: base64url: %w", err)
		}
		return b, nil
	default:
		return nil, fmt.Errorf("multibase: unsupported prefix %q", s[0])
	}
}

func encodeBase58BTC(input []byte) string {
	// Count leading zero bytes — each becomes a '1' in base58.
	leadingZeros := 0
	for _, b := range input {
		if b != 0 {
			break
		}
		leadingZeros++
	}

	n := new(big.Int).SetBytes(input)
	var digits []byte
	mod := new(big.Int)
	for n.Cmp(bigZero) > 0 {
		n.DivMod(n, bigBase, mod)
		digits = append(digits, alphabet[mod.Int64()])
	}

	// Prepend leading '1's for zero bytes.
	result := strings.Repeat("1", leadingZeros)
	// digits are in reverse order.
	for i := len(digits) - 1; i >= 0; i-- {
		result += string(digits[i])
	}
	return result
}

func decodeBase58BTC(s string) ([]byte, error) {
	n := new(big.Int)
	for _, c := range []byte(s) {
		v := decTable[c]
		if v == 255 {
			return nil, fmt.Errorf("invalid base58 character %q", c)
		}
		n.Mul(n, bigBase)
		n.Add(n, big.NewInt(int64(v)))
	}

	decoded := n.Bytes()

	// Restore leading zero bytes for each leading '1'.
	leadingZeros := 0
	for _, c := range s {
		if c != '1' {
			break
		}
		leadingZeros++
	}

	result := make([]byte, leadingZeros+len(decoded))
	copy(result[leadingZeros:], decoded)
	return result, nil
}
