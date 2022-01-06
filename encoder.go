package jwt

import (
	"encoding/base64"
	"encoding/json"
)

type Encoder struct {
	secret        []byte
	headers       headers
	encodedHeader string
	algorithm     Algorithm
}

func NewEncoder(options ...EncoderOption) *Encoder {
	this := &Encoder{headers: headers{Type: "JWT"}}
	for _, option := range options {
		option(this)
	}
	if this.algorithm == nil {
		WithEncodingAlgorithm(HS256{})(this)
	}

	this.encodedHeader = this.header()
	return this
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
	return this.algorithm.ComputeHash([]byte(token), this.secret)
}
func base64Encode(in []byte) string {
	return base64.RawURLEncoding.EncodeToString(in)
}
