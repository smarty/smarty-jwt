package jwt

import "time"

type StandardClaims struct {
	Expiration int64  `json:"exp,omitempty"`
	Audience   string `json:"aud,omitempty"`
}

func (this StandardClaims) TokenExpiration() time.Time { return time.Unix(this.Expiration, 0).UTC() }
func (this StandardClaims) TokenAudience() string      { return this.Audience }
