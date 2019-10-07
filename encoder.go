package jwt

import (
	"encoding/base64"
	"encoding/json"
)

type Encoder struct {

}

func NewEncoder() *Encoder {
	return &Encoder{}
}

func (this *Encoder) Encode(claims interface{}) string {
	jsonStuff, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(jsonStuff)
}
