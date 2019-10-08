package jwt

type Serializer interface {
	Serialize(interface{}) []byte
}

type ClaimCallback func(claims map[string]interface{}, data interface{})

type Expiration interface {
	SetExpiration(int64)
}

type Issuer interface {
	SetIssuer(string)
}
