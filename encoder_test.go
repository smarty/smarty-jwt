package jwt

import (
	"testing"
	"time"

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
	encoder := NewEncoder(WithEncoderAlgorithm(NoAlgorithm{}))

	original := rfcExample{
		Issuer:     "joe",
		Expiration: 1300819380,
	}

	token, err := encoder.Encode(original)

	this.So(err, should.BeNil)
	this.assertNoSignature(token)
	this.So(this.decodeToken(token, nil), should.Resemble, original)
}

func (this *EncoderFixture) assertNoSignature(token string) bool {
	return this.So(token, should.EndWith, ".")
}

func (this *EncoderFixture) decodeToken(token string, secret []byte) (decoded rfcExample) {
	decoder := NewDecoder(
		WithValidator(NewDefaultValidator()),
		WithSecretCallback(func(id string) []byte { return secret }),
		WithDecoderAlgorithm(NoAlgorithm{}), WithDecoderAlgorithm(HS256{}),
	)
	_ = decoder.Decode(token, &decoded)
	return decoded
}

func (this *EncoderFixture) TestEncodeWithSignature() {
	encoder := NewEncoder(WithEncoderSecret("id", []byte("secret")), WithEncoderAlgorithm(HS256{}))

	original := rfcExample{
		Issuer:     "joe",
		Expiration: 1300819380,
	}

	token, err := encoder.Encode(original)

	this.So(err, should.BeNil)
	this.So(this.decodeToken(token, []byte("secret")), should.Resemble, original)
}

func (this *EncoderFixture) TestEncodingFailsWhenSerializationFails() {
	encoder := NewEncoder(WithEncoderAlgorithm(NoAlgorithm{}))

	token, err := encoder.Encode(make(chan int))

	this.So(err, should.NotBeNil)
	this.So(token, should.BeBlank)
}

func (this *EncoderFixture) TestDefaultOptions() {
	encoder := NewEncoder()
	defaultEncoder := NewEncoder(WithEncoderAlgorithm(NoAlgorithm{}), WithEncoderSecret("", nil))

	data := rfcExample{
		Issuer:     "test",
		Expiration: time.Now().Add(time.Hour).Unix(),
	}

	expected, _ := defaultEncoder.Encode(data)
	actual, _ := encoder.Encode(data)

	this.So(actual, should.Equal, expected)
}
