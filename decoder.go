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
	claimCallbacks []ClaimCallback
	secret         func(id string) []byte
	algorithms     map[string]hash.Hash
}

// TODO: parameter for allowed signing algorithms (from config). Default: HS256
// TODO: promote hash algorithms to first-class concept/interface.
func NewDecoder(secret func(id string) []byte, claimCallbacks ...ClaimCallback) *Decoder {
	return &Decoder{secret: secret, claimCallbacks: claimCallbacks}
}

func (this Decoder) Decode(token string, claims interface{}) error {
	payloadBytes, err := parseToken(token, this.secret)
	if err != nil {
		return err
	}

	payload, err := deserializeClaims(payloadBytes)
	if err != nil {
		return err
	}

	this.parseClaims(payload, claims)

	return nil
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

func (this Decoder) parseClaims(claimValues map[string]interface{}, claims interface{}) {
	for _, callback := range this.claimCallbacks {
		callback(claimValues, claims)
	}
}

func deserializeClaims(payloadBytes []byte) (parsedClaims map[string]interface{}, err error) {
	if json.Unmarshal(payloadBytes, &parsedClaims) != nil {
		return nil, MalformedPayloadContentErr
	}
	return parsedClaims, nil
}

func base64Decode(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(value)
}
