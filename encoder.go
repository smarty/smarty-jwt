package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
)

type Encoder struct {
	secret        []byte
	headers       headers
	encodedHeader string
}

func NewEncoder(options ...EncoderOption) *Encoder {
	encoder := &Encoder{headers: headers{Type: "JWT"}}
	for _, option := range options {
		option(encoder)
	}
	encoder.encodedHeader = encoder.header()
	return encoder
}

type EncoderOption func(encoder *Encoder)

func Algorithm(algorithm string) EncoderOption {
	return func(encoder *Encoder) {
		encoder.headers.Algorithm = algorithm
	}
}
func Secret(id string, secret []byte) EncoderOption {
	return func(encoder *Encoder) {
		encoder.headers.KeyID = id
		encoder.secret = secret
	}
}

func (this *Encoder) Encode(claims interface{}) (token string, err error) {
	serialized, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return this.composeToken(serialized), nil
}
func (this *Encoder) composeToken(serialized []byte) (token string) {
	token += this.encodedHeader
	token += this.payload(serialized)
	token += this.signature(token)
	return token
}
func (this *Encoder) header() string {
	serialized, _ := json.Marshal(this.headers)
	return base64Encode(serialized)
}
func (this *Encoder) payload(serialized []byte) string {
	return "." + base64Encode(serialized)
}
func (this *Encoder) signature(token string) string {
	return "." + base64Encode(this.calculateSignature(token))
}
func (this *Encoder) calculateSignature(token string) []byte {
	return hash(token, this.secret)
}
func hash(src string, secret []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(src))
	return h.Sum(nil)
}
func base64Encode(in []byte) string {
	return base64.RawURLEncoding.EncodeToString(in)
}
