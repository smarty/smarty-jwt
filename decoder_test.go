package jwt

import (
	"testing"

	"github.com/smartystreets/assertions/should"
	"github.com/smartystreets/gunit"
)

func TestDecoderFixture(t *testing.T) {
    gunit.Run(new(DecoderFixture), t)
}

type DecoderFixture struct {
    *gunit.Fixture
    decoder *Decoder
}

func (this *DecoderFixture) Setup() {
	this.decoder = NewDecoder()
}

func (this *DecoderFixture) TestDecode() {
	token :="eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
	var claims parsedPayload

	err := this.decoder.Decode(token, &claims)

	this.So(err, should.BeNil)
	this.So(claims.Issuer, should.Equal, "joe")
}


type parsedPayload struct {
	Issuer string
}

func (this *parsedPayload) SetIssuer(value string) {
	this.Issuer = value
}
