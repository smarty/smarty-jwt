package jwt

import "errors"

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

var SegmentCountErr = errors.New("a JWT must have three segments separated by period characters")
var MalformedHeaderErr = errors.New("the header was malformed")
