package jwt

import (
	"testing"

	"github.com/smartystreets/assertions/should"
	"github.com/smartystreets/gunit"
)

type rfcExample struct {
	Issuer     string `json:"iss"`
	Expiration int64  `json:"exp"`
}

func TestEncoderFixture(t *testing.T) {
	gunit.Run(new(EncoderFixture), t)
}

type EncoderFixture struct {
	*gunit.Fixture
}

func (this *EncoderFixture) TestEncode() {
	encoder := NewEncoder(WithAlgorithm(NoAlgorithm{}))

	original := rfcExample{
		Issuer:     "joe",
		Expiration: 1300819380,
	}

	token, err := encoder.Encode(original)

	this.So(err, should.BeNil)
	this.So(this.decodeToken(token, nil), should.Resemble, original)
}

func (this *EncoderFixture) decodeToken(token string, secret []byte) (decoded rfcExample) {
	decoder := NewDecoder(func(id string) []byte { return secret }, NewDefaultValidator())
	_ = decoder.Decode(token, &decoded)
	return decoded
}

func (this *EncoderFixture) TestEncodeWithSignature() {
	encoder := NewEncoder(WithSecret("id", []byte("secret")), WithAlgorithm(HS256{}))

	original := rfcExample{
		Issuer:     "joe",
		Expiration: 1300819380,
	}

	token, err := encoder.Encode(original)

	this.So(err, should.BeNil)
	this.So(this.decodeToken(token, []byte("secret")), should.Resemble, original)
}

func (this *EncoderFixture) TestEncodingFailsWhenSerializationFails() {
	encoder := NewEncoder(WithAlgorithm(NoAlgorithm{}))

	token, err := encoder.Encode(make(chan int))

	this.So(err, should.NotBeNil)
	this.So(token, should.BeBlank)
}
