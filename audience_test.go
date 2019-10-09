package jwt

// TODO move claims into a separate "claims" package?

import (
	"testing"

	"github.com/smartystreets/assertions/should"
	"github.com/smartystreets/gunit"
)

func TestAudienceFixture(t *testing.T) {
	gunit.Run(new(AudienceFixture), t)
}

type AudienceFixture struct {
	*gunit.Fixture
	claims   map[string]interface{}
	audience string
}

func (this *AudienceFixture) Setup() {
	this.claims = map[string]interface{}{}
}

func (this *AudienceFixture) TestAudienceParsed() {
	this.claims["aud"] = "audience"

	ParseAudience(this.claims, this)

	this.So(this.audience, should.Equal, "audience")
}

func (this *AudienceFixture) TestAudienceCannotBeCast() {
	ParseAudience(this.claims, nil)

	this.So(this.audience, should.BeEmpty)
}

func (this *AudienceFixture) TestMalformedAudience() {
	this.claims["aud"] = 0

	ParseAudience(this.claims, this)

	this.So(this.audience, should.BeEmpty)
}

/////////////////////////////////////////////////////////////////////////////////////

func (this *AudienceFixture) SetAudience(audience string) {
	this.audience = audience
}
