package jwt

import (
	"encoding/base64"
)

type Encoder struct {
	serializer Serializer
}

func NewEncoder(serializer Serializer) *Encoder {
	return &Encoder{serializer: serializer}
}

func (this *Encoder) Encode(claims interface{}) string {
	header := this.serializer.Serialize(map[string]string{"alg": "none"})
	payload := this.serializer.Serialize(claims)
	encodedHeader := base64.RawURLEncoding.EncodeToString(header)
	encodedBody := base64.RawURLEncoding.EncodeToString(payload)
	return encodedHeader + "." + encodedBody + "."
}

// TODO: "iss" must be a string or URI
