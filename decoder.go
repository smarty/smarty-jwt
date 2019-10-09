package jwt

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

type Decoder struct {
	claimCallbacks []ClaimCallback
	secret         []byte
}

func NewDecoder(claimCallbacks ...ClaimCallback) *Decoder {
	return &Decoder{claimCallbacks: claimCallbacks}
}

func (this Decoder) Decode(token string, claims interface{}) error {
	// TODO if length of jwt after splitting != 3, bail with an error

	data := strings.Split(token, ".")

	header := data[0]
	headerBytes, _ := base64.RawURLEncoding.DecodeString(header)
	var headerValues map[string]interface{}
	_ = json.Unmarshal(headerBytes, &headerValues)

	payload := data[1]
	payloadBytes, _ := base64.RawURLEncoding.DecodeString(payload)

	if headerValues["alg"] != "none" {
		signature := data[2]
		signatureBytes, _ := base64.RawURLEncoding.DecodeString(signature)
		hash := Hash(data[0]+"."+data[1], this.secret)
		if subtle.ConstantTimeCompare(signatureBytes, hash) == 0 {
			return errors.New("bad signature")
		}
	}

	var parsedClaims map[string]interface{}
	_ = json.Unmarshal(payloadBytes, &parsedClaims)

	for _, callback := range this.claimCallbacks {
		callback(parsedClaims, claims)
	}

	return nil
}

func (this *Decoder) SetSecret(secret []byte) {
	this.secret = secret
}
