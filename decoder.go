package jwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

type Decoder struct {
	claimCallbacks []ClaimCallback
}

func NewDecoder(claimCallbacks ...ClaimCallback) *Decoder {
	return &Decoder{claimCallbacks: claimCallbacks}
}

func (this Decoder) Decode(token string, claims interface{}) error {
	data := strings.Split(token, ".")
	payload := data[1]
	payloadBytes, _ := base64.RawURLEncoding.DecodeString(payload)

	var m map[string]interface{} // TODO: better name
	_ = json.Unmarshal(payloadBytes, &m)

	for _, callback := range this.claimCallbacks {
		callback(m, claims)
	}

	expiration := claims.(Expiration)  // TODO protect cost
	value := int64(m["exp"].(float64)) // TODO protect cast
	expiration.SetExpiration(value)

	return nil
}
