package jwt

type JSONSerializer interface {
	Serialize(interface{}) []byte
}

type ClaimCallback func(claims map[string]interface{}, data interface{})

type Expiration interface {
	SetExpiration(int64)
}

type Issuer interface {
	SetIssuer(string)
}

type Audience interface {
	SetAudience(...string)
}

type Scope interface {
	SetScope(string)
}
