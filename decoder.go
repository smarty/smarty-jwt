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

	var parsedClaims map[string]interface{}
	_ = json.Unmarshal(payloadBytes, &parsedClaims)

	for _, callback := range this.claimCallbacks {
		callback(parsedClaims, claims)
	}

	return nil
}
