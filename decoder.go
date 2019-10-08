package jwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

type Decoder struct {
}

func NewDecoder() *Decoder {
	return &Decoder{}
}

func (this Decoder) Decode(token string, claims interface{}) error {
	data := strings.Split(token, ".")
	payload := data[1]
	payloadBytes, _ := base64.RawURLEncoding.DecodeString(payload)

	var m map[string]interface{}
	_ = json.Unmarshal(payloadBytes, &m)

	if issuer, ok := claims.(Issuer); ok {
		issuer.SetIssuer(m["iss"].(string)) // TODO protect cast
	}

	return nil
}

type Issuer interface {
	SetIssuer(string)
}
