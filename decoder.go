package jwt

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"strings"
)

type Decoder struct {
	secret     func(id string) []byte
	algorithms map[string]Algorithm
	validator  Validator
}

func NewDecoder(options ...DecoderOption) *Decoder {
	this := &Decoder{algorithms: map[string]Algorithm{}}
	this.setOptions(options)
	this.setDefaultOptions()
	return this
}
func (this *Decoder) setOptions(options []DecoderOption) {
	for _, option := range options {
		option(this)
	}
}
func (this *Decoder) setDefaultOptions() {
	this.setDefaultValidator()
	this.setDefaultSecretCallback()
	this.setDefaultAlgorithm()
}
func (this *Decoder) setDefaultAlgorithm() {
	if len(this.algorithms) == 0 {
		WithDecodingAlgorithm(HS256{})(this)
	}
}
func (this *Decoder) setDefaultSecretCallback() {
	if this.secret == nil {
		WithDecodingSecrets(noSecret)(this)
	}
}
func (this *Decoder) setDefaultValidator() {
	if this.validator == nil {
		WithDecodingValidator(NewDefaultValidator())(this)
	}
}

func (this Decoder) Decode(token string, claims interface{}) error {
	payloadBytes, err := this.parseToken(token)
	if err != nil {
		return err
	}

	if err = deserializeClaims(payloadBytes, claims); err != nil {
		return err
	}

	return this.validator.Validate(claims)
}
func (this *Decoder) parseToken(token string) ([]byte, error) {
	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		return nil, SegmentCountErr
	}
	var header headers
	if err := unmarshalHeader(segments[0], &header); err != nil {
		return nil, err
	}
	if err := this.validateSignature(header, segments); err != nil {
		return nil, err
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

func (this *Decoder) validateSignature(header headers, segments []string) error {
	algorithm, found := this.algorithms[header.Algorithm]
	if !found {
		return UnrecognizedAlgorithmErr
	}
	providedSignature, err := base64Decode(segments[2])
	if err != nil {
		return MalformedSignatureErr
	}
	computedSignature := algorithm.ComputeHash([]byte(segments[0]+"."+segments[1]), this.secret(header.KeyID))
	if subtle.ConstantTimeCompare(providedSignature, computedSignature) != 1 {
		return UnrecognizedSignatureErr
	}
	return nil
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
