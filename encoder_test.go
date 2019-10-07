package jwt

import (
	"testing"

	"github.com/smartystreets/assertions/should"
	"github.com/smartystreets/gunit"
)

type rfcExample struct {
	Issuer string `json:"iss"`
	Expiration int `json:"exp"`
	URL bool `json:"http://example.com/is_root"`
}

func TestEncoderFixture(t *testing.T) {
	gunit.Run(new(EncoderFixture), t)
}

type EncoderFixture struct {
	*gunit.Fixture
	encoder *Encoder
}

func (this *EncoderFixture) Setup() {
	this.encoder = NewEncoder()
}

func (this *EncoderFixture) TestEncode() {
	token := this.encoder.Encode(rfcExample{
		Issuer:     "joe",
		Expiration: 1300819380,
		URL:        true,
	})

	this.So(token, should.Equal, "" +
		"eyJhbGciOiJub25lIn0." +
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.")
}
