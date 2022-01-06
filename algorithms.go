package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

type NoAlgorithm struct{}

func (this NoAlgorithm) Name() string                            { return noAlgorithm }
func (this NoAlgorithm) ComputeHash(value, secret []byte) []byte { return nil }

type HS256 struct{}

func (this HS256) Name() string                            { return hs256 }
func (this HS256) ComputeHash(value, secret []byte) []byte { return _hmac(sha256.New, value, secret) }

type HS384 struct{}

func (this HS384) Name() string { return hs384 }
func (this HS384) ComputeHash(value, secret []byte) []byte {
	return _hmac(sha512.New384, value, secret)
}

type HS512 struct{}

func (this HS512) Name() string                            { return hs512 }
func (this HS512) ComputeHash(value, secret []byte) []byte { return _hmac(sha512.New, value, secret) }

func _hmac(algorithm func() hash.Hash, value, secret []byte) []byte {
	hasher := hmac.New(algorithm, secret)
	hasher.Write(value)
	return hasher.Sum(nil)
}

func translateNamedAlgorithm(name string) Algorithm {
	switch name {
	case noAlgorithm:
		return NoAlgorithm{}
	case hs256:
		return HS256{}
	case hs384:
		return HS384{}
	case hs512:
		return HS512{}
	default:
		panic("unknown algorithm")
	}
}

const (
	noAlgorithm = "none"
	hs256       = "HS256"
	hs384       = "HS384"
	hs512       = "HS512"
)
