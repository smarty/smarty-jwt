package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
)

type Encoder struct {
	secret  []byte
	headers map[string]string
}

func NewEncoder(options ...EncoderOption) *Encoder {
	encoder := &Encoder{headers: map[string]string{}}
	for _, option := range options {
		option(encoder)
	}
	return encoder
}

type EncoderOption func(encoder *Encoder)

func Algorithm(algorithm string) EncoderOption {
	return func(encoder *Encoder) {
		encoder.headers["alg"] = algorithm
	}
}
func Secret(id string, secret []byte) EncoderOption {
	return func(encoder *Encoder) {
		encoder.headers["kid"] = id
		encoder.secret = secret
	}
}

func hash(src string, secret []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(src))
	return h.Sum(nil)
}

func (this *Encoder) Encode(claims interface{}) (token string) {
	token += this.header()
	token += this.payload(claims)
	token += this.signature(token)
	return token
}
func (this *Encoder) header() string {
	serialized, _ := json.Marshal(this.headers)
	return this.base64(serialized)
}
func (this *Encoder) payload(claims interface{}) string {
	serialized, _ := json.Marshal(claims)
	return "." + this.base64(serialized)
}
func (this *Encoder) signature(token string) string {
	return "." + this.base64(this.calculateSignature(token))
}
func (this *Encoder) base64(in []byte) string {
	return base64.RawURLEncoding.EncodeToString(in)
}
func (this *Encoder) calculateSignature(token string) []byte {
	if this.headers["alg"] == "none" {
		return nil
	} else {
		return hash(token, this.secret)
	}
}
