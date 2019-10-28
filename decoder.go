package jwt

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"hash"
	"strings"
)

type Decoder struct {
	secret     func(id string) []byte
	algorithms map[string]hash.Hash
}

// TODO: parameter for allowed signing algorithms (from config). Default: HS256
// TODO: promote hash algorithms to first-class concept/interface.
func NewDecoder(secret func(id string) []byte) *Decoder {
	return &Decoder{secret: secret}
}

func (this Decoder) Decode(token string, claims interface{}) error {
	payloadBytes, err := parseToken(token, this.secret)
	if err != nil {
		return err
	}

	return deserializeClaims(payloadBytes, claims) // TODO test to ensure object being passed in for claims has the right fields
	// TODO ask claim if it supports expiration
}

func parseToken(token string, secret func(id string) []byte) ([]byte, error) {
	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		return nil, SegmentCountErr
	}
	var header headers
	err := unmarshalHeader(segments[0], &header)
	if err != nil {
		return nil, err
	}
	if header.Algorithm != "none" {
		if header.KeyID == "" {
			return nil, MissingKIDErr
		}
		err := validateSignature(segments, secret(header.KeyID))
		if err != nil {
			return nil, err
		}
	}
	return base64Decode(segments[1])
}

func unmarshalHeader(data string, header *headers) error {
	headerBytes, err := base64Decode(data)
	if err != nil {
		return MalformedHeaderErr
	}

	if json.Unmarshal(headerBytes, header) != nil {
		return MalformedHeaderContentErr
	}

	return nil
}
func validateSignature(segments []string, secret []byte) error {
	providedSignature, err := base64Decode(segments[2])
	if err != nil {
		return MalformedSignatureErr
	}
	computedSignature := hs256(segments[0]+"."+segments[1], secret)
	comparison := subtle.ConstantTimeCompare(providedSignature, computedSignature)
	if comparison == 1 {
		return nil
	}
	return errors.New("bad signature")
}

func deserializeClaims(payload []byte, claims interface{}) error {
	if json.Unmarshal(payload, &claims) != nil {
		return MalformedPayloadContentErr
	}
	return nil
}

func base64Decode(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(value)
}
