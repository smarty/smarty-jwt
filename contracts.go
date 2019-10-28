package jwt

import (
	"errors"
	"time"
)

type headers struct {
	Algorithm string `json:"alg,omitempty"`
	KeyID     string `json:"kid,omitempty"`
	Type      string `json:"typ,omitempty"`
}

type Validator interface {
	Validate(interface{}) error
}

type TokenExpiration interface {
	TokenExpiration() time.Time
}

type TokenAudience interface {
	TokenAudience() string
}

type Algorithm interface {
	Name() string
	ComputeHash(value, secret []byte) []byte
}

var (
	SegmentCountErr            = errors.New("a JWT must have three segments separated by period characters")
	MalformedHeaderErr         = errors.New("the header is malformed")
	MalformedHeaderContentErr  = errors.New("the header content is malformed")
	MalformedPayloadContentErr = errors.New("the payload content is malformed")
	MalformedSignatureErr      = errors.New("the signature is malformed")
	MissingKeyIDErr            = errors.New("the key ID (kid) is required")
)
