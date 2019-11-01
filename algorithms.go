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
func (this HS256) ComputeHash(value, secret []byte) []byte { return _hash(sha256.New, value, secret) }

type HS384 struct{}

func (this HS384) Name() string                            { return hs384 }
func (this HS384) ComputeHash(value, secret []byte) []byte { return _hash(sha512.New, value, secret) }

type HS512 struct{}

func (this HS512) Name() string                            { return hs512 }
func (this HS512) ComputeHash(value, secret []byte) []byte { return _hash(sha512.New, value, secret) }

func _hash(algorithm func() hash.Hash, value, secret []byte) []byte {
	hasher := hmac.New(algorithm, secret)
	hasher.Write(value)
	return hasher.Sum(nil)
}

const (
	noAlgorithm = "none"
	hs256       = "HS256"
	hs384       = "HS384"
	hs512       = "HS512"
)
