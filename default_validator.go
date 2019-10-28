package jwt

import (
	"errors"
	"time"
)

type DefaultValidator struct {
	now       func() time.Time
	audiences map[string]struct{}
}

func NewDefaultValidator(audiences ...string) DefaultValidator {
	allowed := make(map[string]struct{}, len(audiences))
	for _, aud := range audiences {
		allowed[aud] = struct{}{}
	}
	return DefaultValidator{now: time.Now, audiences: allowed}
}

func (this DefaultValidator) Validate(claim interface{}) error {
	if exp, ok := claim.(TokenExpiration); !this.isCurrent(exp, ok) {
		return TokenExpiredErr
	}
	if aud, ok := claim.(TokenAudience); !this.hasCorrectAudiences(aud, ok) {
		return InvalidAudienceErr
	}

	return nil
}

func (this DefaultValidator) hasCorrectAudiences(claim TokenAudience, hasAudience bool) bool {
	if !hasAudience {
		return true
	}
	_, ok := this.audiences[claim.TokenAudience()]
	return ok
}

func (this DefaultValidator) isCurrent(claim TokenExpiration, hasExpiration bool) bool {
	return !hasExpiration || claim.TokenExpiration().After(this.now())
}

var TokenExpiredErr = errors.New("the token is expired")
var InvalidAudienceErr = errors.New("the audience is invalid")
