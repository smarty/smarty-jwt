package jwt

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

type Decoder struct {
	claimCallbacks []ClaimCallback
	secret         func(id string) []byte
}

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
	header, err := unmarshalHeader(segments[0])
	if err != nil {
		return nil, err
	}
	if header["alg"] != "none" {
		kid, ok := header["kid"].(string)
		if !ok {
			return nil, MissingKIDErr
		}
		err := validateSignature(segments, secret(kid))
		if err != nil {
			return nil, err
		}
	}
	return base64.RawURLEncoding.DecodeString(segments[1])
}
func unmarshalHeader(data string) (header map[string]interface{}, err error) {
	headerBytes, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		return nil, MalformedHeaderErr
	}

	if json.Unmarshal(headerBytes, &header) != nil {
		return nil, MalformedHeaderContentErr
	}

	return header, nil
}
func validateSignature(segments []string, secret []byte) error {
	providedSignature, err := base64.RawURLEncoding.DecodeString(segments[2])
	if err != nil {
		return MalformedSignatureErr
	}
	computedSignature := hash(segments[0]+"."+segments[1], secret)
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
