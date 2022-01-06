package jwt

import (
	"errors"
	"io"
	"time"
)

type Encoder1 interface {
	Encode(io.Writer, interface{}) error
}
type Decoder1 interface {
	Decode(interface{}, io.Reader) error
}

type Algorithm interface {
	Name() string
	ComputeHash(value, secret []byte) []byte
}

type Validator interface {
	Validate(claims interface{}) error
}

type TokenExpiration interface {
	TokenExpiration() time.Time
}

type TokenAudience interface {
	TokenAudience() string
}

type headers struct {
	Algorithm string `json:"alg,omitempty"`
	KeyID     string `json:"kid,omitempty"`
	Type      string `json:"typ,omitempty"`
}

var (
	SegmentCountErr            = errors.New("a JWT must have three segments separated by period characters")
	MalformedHeaderErr         = errors.New("the header is malformed")
	MalformedHeaderContentErr  = errors.New("the header content is malformed")
	MalformedPayloadContentErr = errors.New("the payload content is malformed")
	MalformedSignatureErr      = errors.New("the signature is malformed")
	UnrecognizedSignatureErr   = errors.New("unrecognized signature")
	UnrecognizedAlgorithmErr   = errors.New("unrecognized algorithm")
)
