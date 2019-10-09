package jwt

import (
	"encoding/base64"
	"strings"
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
	this.decoder = NewDecoder(ParseIssuer, ParseExpiration)
}

func (this *DecoderFixture) TestDecodeWithoutSignature() {
	token := "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."

	var claims parsedPayload

	err := this.decoder.Decode(token, &claims)

	this.So(err, should.BeNil)
	this.So(claims.Issuer, should.Equal, "joe")
	this.So(claims.Expiration, should.Equal, 1300819380)
}

func (this *DecoderFixture) TestDecodeValidSignature() {
	encoder := NewEncoder()
	encoder.setAlgorithm("HS256")
	secret := []byte("secret")
	encoder.setSecret(secret)

	token := encoder.Encode(rfcExample{
		Issuer:     "joe",
		Expiration: 1300819380,
		IsRoot:     true,
	})

	var claims parsedPayload

	this.decoder.SetSecret(secret)
	err := this.decoder.Decode(token, &claims)

	this.So(err, should.BeNil)
	this.So(claims.Expiration, should.Equal, 1300819380)
	this.So(claims.Issuer, should.Equal, "joe")
}

func (this *DecoderFixture) TestDecodeInvalidWellFormedSignature() {
	encoder := NewEncoder()
	encoder.setAlgorithm("HS256")
	secret := []byte("secret")
	encoder.setSecret(secret)
	token := encoder.Encode(rfcExample{
		Issuer:     "joe",
		Expiration: 1300819380,
		IsRoot:     true,
	})

	parsedToken := strings.Split(token, ".")
	parsedToken[2] = base64.RawURLEncoding.EncodeToString(Hash("badToken", secret))
	token = strings.Join(parsedToken, ".")

	var claims parsedPayload

	err := this.decoder.Decode(token, &claims)

	this.So(err, should.NotBeNil)
	this.So(claims.Expiration, should.Equal, 0)
	this.So(claims.Issuer, should.BeBlank)
}

type parsedPayload struct {
	Issuer     string
	Expiration int64
}

func (this *parsedPayload) SetIssuer(value string) {
	this.Issuer = value
}

func (this *parsedPayload) SetExpiration(value int64) {
	this.Expiration = value
}
