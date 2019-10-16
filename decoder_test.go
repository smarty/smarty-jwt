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
	encoder *Encoder
}

func (this *DecoderFixture) Setup() {
	this.encoder = NewEncoder(Algorithm("none"))
	this.decoder = NewDecoder(func(id string) []byte { return []byte("secret") }, ParseIssuer, ParseExpiration)
}

func (this *DecoderFixture) TestDecodeWithoutSignature() {
	token, _ := this.encoder.Encode(rfcExample{
		Issuer:     "joe",
		Expiration: 1300819380,
	})

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
	encoder := NewEncoder(Algorithm("HS256"), Secret("id", secret))
	token, _ := encoder.Encode(rfcExample{
		Issuer:     "joe",
		Expiration: 1300819380,
	})
	return token
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
	token := this.encodeTokenWithMalformedHeader()

	err := this.decoder.Decode(token, nil)

	this.So(err, should.Equal, MalformedHeaderErr)
}

func (this *DecoderFixture) encodeTokenWithMalformedHeader() string {
	token, _ := this.encoder.Encode(rfcExample{
		Issuer:     "joe",
		Expiration: 1300819380,
	})
	return "****** BAD HEADER ******" + token[strings.Index(token, "."):]
}

func (this *DecoderFixture) TestDecodeFailsWhenSignatureIsMalformed() {
	token := this.encodeJWTWithBadSignature()

	err := this.decoder.Decode(token, nil)

	this.So(err, should.Equal, MalformedSignatureErr)
}

func (this *DecoderFixture) encodeJWTWithBadSignature() string {
	this.encoder = NewEncoder(Algorithm("HS256"), Secret("kid", nil))
	token, _ := this.encoder.Encode(rfcExample{
		Issuer:     "joe",
		Expiration: 1300819380,
	})
	return token[:strings.LastIndex(token, ".")+1] + "********* BAD SIGNATURE ********"
}

func (this *DecoderFixture) TestUnmarshalHeaderFailsWhenJsonIsMalformed() {
	token := "BAD-HEADER-BUT-GOOD-BASE64.asdf."

	err := this.decoder.Decode(token, nil)

	this.So(err, should.Equal, MalformedHeaderContentErr)
}
func (this *DecoderFixture) TestUnmarshalPayloadFailsWhenJsonIsMalformed() {
	token := "eyJhbGciOiJub25lIn0.BAD-PAYLOAD-BUT-GOOD-BASE64."

	err := this.decoder.Decode(token, nil)

	this.So(err, should.Equal, MalformedPayloadContentErr)
}
func (this *DecoderFixture) TestKIDIsRequiredForSignatureValidation() {
	token := this.encodeTokenWithoutKID()

	err := this.decoder.Decode(token, nil)

	this.So(err, should.Equal, MissingKIDErr)
}

func (this *DecoderFixture) encodeTokenWithoutKID() string {
	encoder := NewEncoder(Algorithm("HS256"), Secret("", nil))
	token, _ := encoder.Encode(rfcExample{
		Issuer:     "joe",
		Expiration: 1300819380,
	})
	return token
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
