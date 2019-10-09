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
	secret         []byte
}

func NewDecoder(secret []byte, claimCallbacks ...ClaimCallback) *Decoder {
	return &Decoder{secret: secret, claimCallbacks: claimCallbacks}
}

func (this Decoder) Decode(token string, claims interface{}) error {
	payloadBytes, err := parseToken(token, this.secret)
	if err != nil {
		return err
	}

	this.parseClaims(deserializeClaims(payloadBytes), claims)

	return nil
}

func parseToken(token string, secret []byte) ([]byte, error) {
	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		return nil, SegmentCountErr
	}
	header, err := unmarshalHeader(segments[0])
	if err != nil {
		return nil, err
	}
	if header["alg"] != "none" && !signatureIsValid(segments, secret) {
		return nil, errors.New("bad signature")
	}
	return base64.RawURLEncoding.DecodeString(segments[1])
}
func unmarshalHeader(data string) (header map[string]interface{}, err error) {
	headerBytes, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		return nil, MalformedHeaderErr
	}
	_ = json.Unmarshal(headerBytes, &header) // TODO test ignored err
	return header, err
}
func signatureIsValid(segments []string, secret []byte) bool {
	providedSignature, _ := base64.RawURLEncoding.DecodeString(segments[2]) // TODO test ignored err
	computedSignature := hash(segments[0]+"."+segments[1], secret)
	return subtle.ConstantTimeCompare(providedSignature, computedSignature) == 1
}

func (this Decoder) parseClaims(claimValues map[string]interface{}, claims interface{}) {
	for _, callback := range this.claimCallbacks {
		callback(claimValues, claims)
	}
}

func deserializeClaims(payloadBytes []byte) (parsedClaims map[string]interface{}) {
	_ = json.Unmarshal(payloadBytes, &parsedClaims) // TODO test ignored err
	return parsedClaims
}
