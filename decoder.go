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

	var m map[string]interface{} // TODO: better name
	_ = json.Unmarshal(payloadBytes, &m)

	issuer := claims.(Issuer)           // TODO protect cast
	issuer.SetIssuer(m["iss"].(string)) // TODO protect cast

	expiration := claims.(Expiration)  // TODO protect cost
	value := int64(m["exp"].(float64)) // TODO protect cast
	expiration.SetExpiration(value)

	return nil
}

type Expiration interface {
	SetExpiration(int64)
}

type Issuer interface {
	SetIssuer(string)
}
