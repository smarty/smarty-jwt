package jwt

import (
	"testing"

	"github.com/smartystreets/assertions/should"
	"github.com/smartystreets/gunit"
)

type rfcExample struct {
	Issuer     string `json:"iss"`
	Expiration int    `json:"exp"`
	IsRoot     bool   `json:"http://example.com/is_root"`
}

func TestEncoderFixture(t *testing.T) {
	gunit.Run(new(EncoderFixture), t)
}

type EncoderFixture struct {
	*gunit.Fixture
}

func (this *EncoderFixture) TestEncode() {
	encoder := NewEncoder(Algorithm("none"))

	token, err := encoder.Encode(rfcExample{
		Issuer:     "joe",
		Expiration: 1300819380,
		IsRoot:     true,
	})

	this.So(err, should.BeNil)
	this.So(token, should.Equal, ""+
		"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.")
}

func (this *EncoderFixture) TestEncodeWithSignature() {
	encoder := NewEncoder(Secret("id", []byte("secret")), Algorithm("HS256"))

	token, err := encoder.Encode(rfcExample{
		Issuer:     "joe",
		Expiration: 1300819380,
		IsRoot:     true,
	})

	this.So(err, should.BeNil)
	this.So(token, should.Equal, "eyJhbGciOiJIUzI1NiIsImtpZCI6ImlkIiwidHlwIjoiSldUIn0.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.7TtdM8KDfnEfLolTmhVWlDGw4Bu-3dESXZHAFNIhyD8")
}

func (this *EncoderFixture) TestEncodingFailsWhenSerializationFails() {
	encoder := NewEncoder(Algorithm("none"))

	token, err := encoder.Encode(make(chan int))

	this.So(err, should.NotBeNil)
	this.So(token, should.BeBlank)
}
