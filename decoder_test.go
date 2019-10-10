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
	this.decoder = NewDecoder([]byte("secret"), ParseIssuer, ParseExpiration)
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
	secret := []byte("secret")
	token := generateTokenWithGoodSignature(secret)

	var claims parsedPayload
	err := this.decoder.Decode(token, &claims)

	this.So(err, should.BeNil)
	this.So(claims.Expiration, should.Equal, 1300819380)
	this.So(claims.Issuer, should.Equal, "joe")
}

func (this *DecoderFixture) TestJWTsMustHaveThreeSegmentsToBeDecoded() {
	this.So(this.decoder.Decode("111", nil), should.Equal, SegmentCountErr)
	this.So(this.decoder.Decode("111.222", nil), should.Equal, SegmentCountErr)
	this.So(this.decoder.Decode("111.222.333", nil), should.NotEqual, SegmentCountErr)
	this.So(this.decoder.Decode("111.222.333.444", nil), should.Equal, SegmentCountErr) // FUTURE HS384 ?
}

func generateTokenWithGoodSignature(secret []byte) string {
	encoder := NewEncoder(Algorithm("HS256"), Secret(secret))
	return encoder.Encode(rfcExample{
		Issuer:     "joe",
		Expiration: 1300819380,
		IsRoot:     true,
	})
}

func (this *DecoderFixture) TestDecodeInvalidWellFormedSignature() {
	secret := []byte("secret")
	token := generateTokenWithBadSignature(secret)

	var claims parsedPayload
	err := this.decoder.Decode(token, &claims)

	this.So(err, should.NotBeNil)
	this.So(claims.Expiration, should.Equal, 0)
	this.So(claims.Issuer, should.BeBlank)
}

func generateTokenWithBadSignature(secret []byte) string {
	token := generateTokenWithGoodSignature(secret)
	parsedToken := strings.Split(token, ".")
	parsedToken[2] = base64.RawURLEncoding.EncodeToString(hash("badToken", secret))
	return strings.Join(parsedToken, ".")
}

func (this *DecoderFixture) TestDecodeFailsWhenHeaderIsMalformed() {
	token := "****** BAD HEADER ******.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."

	err := this.decoder.Decode(token, nil)

	this.So(err, should.Equal, MalformedHeaderErr)
}

func (this *DecoderFixture) TestDecodeFailsWhenSignatureIsMalformed() {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
		"********* BAD SIGNATURE ********"

	err := this.decoder.Decode(token, nil)

	this.So(err, should.Equal, MalformedSignatureErr)
}

func (this *DecoderFixture) TestUnmarshalHeaderFailsWhenJsonIsMalformed() {
	token := "BAD-HEADER-BUT-GOOD-BASE64.asdf."

	err := this.decoder.Decode(token, nil)

	this.So(err, should.Equal, MalformedHeaderContentErr)
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
