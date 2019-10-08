package jwt

type Serializer interface {
	Serialize(interface{}) []byte
}
