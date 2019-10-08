package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

type Encoder struct {
	serializer Serializer
	secret     []byte
	headers    map[string]string
}

func NewEncoder() *Encoder {
	return &Encoder{
		serializer: newDefaultSerializer(),
		headers:    map[string]string{"alg": "none"},
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

func (this *Encoder) setAlgorithm(algorithm string)       { this.headers["alg"] = algorithm }
func (this *Encoder) setSecret(secret []byte)             { this.secret = secret }
func (this *Encoder) setSerializer(serializer Serializer) { this.serializer = serializer }

// TODO: "iss" must be a string or URI
