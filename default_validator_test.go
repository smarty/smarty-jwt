package jwt

import (
	"testing"
	"time"

	"github.com/smartystreets/assertions/should"
	"github.com/smartystreets/gunit"
)

func TestDefaultValidatorFixture(t *testing.T) {
	gunit.Run(new(DefaultValidatorFixture), t)
}

type DefaultValidatorFixture struct {
	*gunit.Fixture

	validator Validator
}

func (this *DefaultValidatorFixture) Setup() {
	this.validator = NewDefaultValidator("smarty", "streets")
}

func (this *DefaultValidatorFixture) TestFutureExpirationValid() {
	future := time.Now().Add(time.Hour)
	claim := &sampleClaim{Expiration: future, Audience: "smarty"}

	err := this.validator.Validate(claim)

	this.So(err, should.BeNil)
}

func (this *DefaultValidatorFixture) TestExpirationNotConsideredBecauseInterfaceNotImplemented() {
	err := this.validator.Validate(sampleClaim{})

	this.So(err, should.BeNil)
}

func (this *DefaultValidatorFixture) TestPastExpirationInvalid() {
	past := time.Now().Add(-time.Nanosecond)
	claim := &sampleClaim{Expiration: past, Audience: "smarty"}

	err := this.validator.Validate(claim)

	this.So(err, should.Equal, TokenExpiredErr)
}

func (this *DefaultValidatorFixture) TestAudienceIsValid() {
	this.assertAudience("smarty", nil)
	this.assertAudience("streets", nil)
	this.assertAudience("INVALID", InvalidAudienceErr)
}

func (this *DefaultValidatorFixture) assertAudience(audience string, expectedError error) {
	claim := &sampleClaim{Expiration: time.Now().Add(time.Hour), Audience: audience}

	err := this.validator.Validate(claim)

	this.So(err, should.Equal, expectedError)
}

type sampleClaim struct {
	Expiration time.Time `json:"exp"`
	Audience   string    `json:"aud"`
}

func (this *sampleClaim) TokenExpiration() time.Time { return this.Expiration }
func (this *sampleClaim) TokenAudience() string      { return this.Audience }
