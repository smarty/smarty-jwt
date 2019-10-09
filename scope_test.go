package jwt

import (
	"testing"

	"github.com/smartystreets/assertions/should"
	"github.com/smartystreets/gunit"
)

func TestScopeFixture(t *testing.T) {
	gunit.Run(new(ScopeFixture), t)
}

type ScopeFixture struct {
	*gunit.Fixture
	claims map[string]interface{}
	scope  string
}

func (this *ScopeFixture) Setup() {
	this.claims = map[string]interface{}{}
}

func (this *ScopeFixture) TestScopeParsed() {
	this.claims["scope"] = "scope"

	ParseScope(this.claims, this)

	this.So(this.scope, should.Equal, "scope")
}

func (this *ScopeFixture) TestScopeCannotCast() {
	this.claims["scope"] = "scope"

	ParseScope(this.claims, nil)

	this.So(this.scope, should.BeEmpty)
}

func (this *ScopeFixture) TestMalformedScope() {
	this.claims["scope"] = 0

	ParseScope(this.claims, this)

	this.So(this.scope, should.BeEmpty)
}

/////////////////////////////////////////////////////////////////////

func (this *ScopeFixture) SetScope(scope string) {
	this.scope = scope
}
