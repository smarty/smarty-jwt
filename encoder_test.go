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
	encoder := NewEncoder(WithNamedEncodingAlgorithm("HS384"))

	original := rfcExample{
		Issuer:     "joe",
		Expiration: 1300819380,
	}

	token, err := encoder.Encode(original)

	this.So(err, should.BeNil)
	this.assertSignature(token)
	this.So(this.decodeToken(token, nil), should.Resemble, original)
}

func (this *EncoderFixture) assertSignature(token string) bool {
	return this.So(token, should.NotEndWith, ".")
}

func (this *EncoderFixture) decodeToken(token string, secret []byte) (decoded rfcExample) {
	decoder := NewDecoder(
		WithDecodingValidator(NewDefaultValidator()),
		WithDecodingSecrets(func(id string) []byte { return secret }),
		WithNamedDecodingAlgorithms("none", "HS256", "HS384"),
	)
	_ = decoder.Decode(token, &decoded)
	return decoded
}

func (this *EncoderFixture) TestEncodeWithSignature() {
	encoder := NewEncoder(WithEncodingSecret("id", []byte("secret")), WithEncodingAlgorithm(HS256{}))

	original := rfcExample{
		Issuer:     "joe",
		Expiration: 1300819380,
	}

	token, err := encoder.Encode(original)

	this.So(err, should.BeNil)
	this.So(this.decodeToken(token, []byte("secret")), should.Resemble, original)
}

func (this *EncoderFixture) TestEncodingFailsWhenSerializationFails() {
	encoder := NewEncoder(WithNamedEncodingAlgorithm("none"))

	token, err := encoder.Encode(make(chan int))

	this.So(err, should.NotBeNil)
	this.So(token, should.BeBlank)
}

func (this *EncoderFixture) TestDefaultOptions() {
	encoder := NewEncoder()
	defaultEncoder := NewEncoder(WithEncodingAlgorithm(HS256{}), WithEncodingSecret("", nil))

	data := rfcExample{
		Issuer:     "test",
		Expiration: time.Now().Add(time.Hour).Unix(),
	}

	expected, _ := defaultEncoder.Encode(data)
	actual, _ := encoder.Encode(data)

	this.So(actual, should.Equal, expected)
}
