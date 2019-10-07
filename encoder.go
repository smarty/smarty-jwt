package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type Encoder struct {
}

func NewEncoder() *Encoder {
	return &Encoder{}
}

func (this *Encoder) Encode(claims interface{}) string {
	header, _ := json.Marshal(map[string]string{"alg": "none"})
	payload, _ := json.Marshal(claims)
	//payload = bytes.ReplaceAll(payload, []byte(","), []byte(",\n"))
	fmt.Println(string(payload))
	encodedHeader := base64.RawStdEncoding.EncodeToString(header)
	encodedBody := base64.RawStdEncoding.EncodeToString(payload)
	return encodedHeader + "." + encodedBody + "."
}
