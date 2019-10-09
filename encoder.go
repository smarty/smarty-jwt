package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

type Encoder struct {
	serializer JSONSerializer
	secret     []byte
	headers    map[string]string
}

// TODO: functional options (algorithm, secret, serializer)
func NewEncoder(options ...EncoderOption) *Encoder {
	encoder := &Encoder{
		serializer: newDefaultSerializer(),
		headers:    map[string]string{"alg": "HS256"},
	}
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
func Secret(secret []byte) EncoderOption {
	return func(encoder *Encoder) {
		encoder.secret = secret
	}
}
func Serializer(serializer JSONSerializer) EncoderOption {
	return func(encoder *Encoder) {
		encoder.serializer = serializer
	}
}

// TODO Define with encoder receiver (reuse HMAC)
func Hash(src string, secret []byte) []byte {
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
	return this.base64(this.serializer.Serialize(this.headers))
}
func (this *Encoder) payload(claims interface{}) string {
	return "." + this.base64(this.serializer.Serialize(claims))
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
		return Hash(token, this.secret)
	}
}

// TODO: "iss" must be a string or URI
