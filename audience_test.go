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
	audience []string
}

func (this *AudienceFixture) Setup() {
	this.claims = map[string]interface{}{}
}

func (this *AudienceFixture) TestAudienceParsedWithString() {
	this.claims["aud"] = "audience"

	ParseAudience(this.claims, this)

	this.So(this.audience[0], should.Equal, "audience")
}

func (this *AudienceFixture) TestAudienceParsedWithSlice() {
	this.claims["aud"] = []string{"audience0", "audience1", "audience2"}

	ParseAudience(this.claims, this)

	this.So(this.audience[0], should.Equal, "audience0")
	this.So(this.audience[1], should.Equal, "audience1")
	this.So(this.audience[2], should.Equal, "audience2")
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

func (this *AudienceFixture) SetAudience(audience ...string) {
	this.audience = audience
}
