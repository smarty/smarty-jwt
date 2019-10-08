package jwt

import "encoding/json"

type defaultSerializer struct {
}

func (this *defaultSerializer) Serialize(v interface{}) []byte {
	serialized, _ := json.Marshal(v)
	return serialized
}

func newDefaultSerializer() Serializer {
	return &defaultSerializer{}
}

