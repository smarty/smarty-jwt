package jwt

import "errors"

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
	MissingKIDErr              = errors.New("kid is required")
)
