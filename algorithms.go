package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
)

type NoAlgorithm struct{}

func (this NoAlgorithm) Name() string                            { return "none" }
func (this NoAlgorithm) ComputeHash(value, secret []byte) []byte { return nil }

type HS256 struct{}

func (this HS256) Name() string { return "HS256" }
func (this HS256) ComputeHash(value, secret []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write(value)
	return h.Sum(nil)
}

type HS384 struct{}

func (this HS384) Name() string { return "HS384" }
func (this HS384) ComputeHash(value, secret []byte) []byte {
	h := hmac.New(sha512.New384, secret)
	h.Write(value)
	return h.Sum(nil)
}

type HS512 struct{}

func (this HS512) Name() string { return "HS512" }
func (this HS512) ComputeHash(value, secret []byte) []byte {
	h := hmac.New(sha512.New, secret)
	h.Write(value)
	return h.Sum(nil)
}
