package jwt

import (
	"testing"

	"github.com/smartystreets/assertions/should"
	"github.com/smartystreets/gunit"
)

func TestExpirationCallbackFixture(t *testing.T) {
	gunit.Run(new(ExpirationCallbackFixture), t)
}

type ExpirationCallbackFixture struct {
	*gunit.Fixture
	expiration int64
	claims map[string]interface{}
}

func (this *ExpirationCallbackFixture) Setup() {
	this.claims = map[string]interface{}{}
}

func (this *ExpirationCallbackFixture) TestExpirationParsed() {
	this.claims["exp"] = 123456789

	ParseExpiration(this.claims, this)

	this.So(this.expiration, should.Equal, 123456789)
}

func (this *ExpirationCallbackFixture) TestExpirationCannotBeCast() {
	this.claims["exp"] = 123456789

	ParseExpiration(this.claims, nil)

	this.So(this.expiration, should.Equal, 0)
}

func (this *ExpirationCallbackFixture) TestMalformedExpiration() {
	this.claims["exp"] = "not a time"

	ParseExpiration(this.claims, this)

	this.So(this.expiration, should.Equal, 0)
}

/////////////////////////////////////////////////////////////////////////////////////

func (this *ExpirationCallbackFixture) SetExpiration(value int64) {
	this.expiration = value
}
