package jwt

import "time"

type DefaultClaims struct {
	Expiration int64  `json:"exp,omitempty"`
	Audience   string `json:"aud,omitempty"`
}

func (this DefaultClaims) TokenExpiration() time.Time { return time.Unix(this.Expiration, 0).UTC() }
func (this DefaultClaims) TokenAudience() string      { return this.Audience }
