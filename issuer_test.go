package jwt

import (
	"testing"

	"github.com/smartystreets/assertions/should"
	"github.com/smartystreets/gunit"
)

func TestIssuerCallbackFixture(t *testing.T) {
	gunit.Run(new(IssuerCallbackFixture), t)
}

type IssuerCallbackFixture struct {
	*gunit.Fixture
	issuer string
	claims map[string]interface{}
}

func (this *IssuerCallbackFixture) Setup() {
	this.claims = map[string]interface{}{}
}

func (this *IssuerCallbackFixture) TestIssuerParsed() {
	this.claims["iss"] = "joe"

	ParseIssuer(this.claims, this)

	this.So(this.issuer, should.Equal, "joe")
}

func (this *IssuerCallbackFixture) TestIssuerCannotBeCast() {
	this.claims["iss"] = "joe"

	ParseIssuer(this.claims, nil)

	this.So(this.issuer, should.BeEmpty)
}

func (this *IssuerCallbackFixture) TestMalformedIssuer() {
	this.claims["iss"] = 0

	ParseIssuer(this.claims, this)

	this.So(this.issuer, should.BeEmpty)
}

/////////////////////////////////////////////////////////////////////////////////////

func (this *IssuerCallbackFixture) SetIssuer(value string) {
	this.issuer = value
}
