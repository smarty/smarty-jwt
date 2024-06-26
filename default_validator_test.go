package jwt

import (
	"testing"
	"time"

	"github.com/smarty/assertions/should"
	"github.com/smarty/gunit"
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
	claim := StandardClaims{Expiration: future.Unix(), Audience: "smarty"}

	err := this.validator.Validate(claim)

	this.So(err, should.BeNil)
}

func (this *DefaultValidatorFixture) TestExpirationNotConsideredBecauseInterfaceNotImplemented() {
	err := this.validator.Validate(0)

	this.So(err, should.BeNil)
}

func (this *DefaultValidatorFixture) TestPastExpirationInvalid() {
	past := time.Now().Add(-time.Nanosecond)
	claim := StandardClaims{Expiration: past.Unix(), Audience: "smarty"}

	err := this.validator.Validate(claim)

	this.So(err, should.Equal, TokenExpiredErr)
}

func (this *DefaultValidatorFixture) TestAudienceIsValid() {
	this.assertAudience("smarty", nil)
	this.assertAudience("streets", nil)
	this.assertAudience("INVALID", InvalidAudienceErr)
}

func (this *DefaultValidatorFixture) assertAudience(audience string, expectedError error) {
	claim := StandardClaims{Expiration: time.Now().Add(time.Hour).Unix(), Audience: audience}

	err := this.validator.Validate(claim)

	this.So(err, should.Equal, expectedError)
}
