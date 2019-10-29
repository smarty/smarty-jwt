package jwt

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/smartystreets/assertions/should"
	"github.com/smartystreets/gunit"
)

func TestDecoderFixture(t *testing.T) {
	gunit.Run(new(DecoderFixture), t)
}

type DecoderFixture struct {
	*gunit.Fixture
	decoder         *Decoder
	encoder         *Encoder
	expiration      int64
	validationErr   error
	validatedClaims interface{}
}

func (this *DecoderFixture) Validate(claims interface{}) error {
	this.validatedClaims = claims
	return this.validationErr
}

func (this *DecoderFixture) Setup() {
	this.encoder = NewEncoder(WithEncoderAlgorithm(NoAlgorithm{}))
	this.decoder = NewDecoder(
		func(id string) []byte { return []byte("secret") },
		this,
		WithDecoderAlgorithm(NoAlgorithm{}), WithDecoderAlgorithm(HS256{}),
	)
	this.expiration = time.Now().Add(time.Hour).Unix()
}

func (this *DecoderFixture) TestDecodeWithoutSignature() {
	token, _ := this.encoder.Encode(rfcExample{
		Issuer:     "joe",
		Expiration: this.expiration,
	})

	var claims parsedPayload
	err := this.decoder.Decode(token, &claims)

	this.So(err, should.BeNil)
	this.So(claims.Issuer, should.Equal, "joe")
	this.So(claims.Expiration, should.Equal, this.expiration)
}

func (this *DecoderFixture) TestDecodeValidSignature() {
	secret := []byte("secret")
	token := this.generateTokenWithGoodSignature(secret)

	var claims parsedPayload
	err := this.decoder.Decode(token, &claims)

	this.So(err, should.BeNil)
	this.So(claims.Expiration, should.Equal, this.expiration)
	this.So(claims.Issuer, should.Equal, "joe")
}

func (this *DecoderFixture) TestJWTsMustHaveThreeSegmentsToBeDecoded() {
	this.So(this.decoder.Decode("111", nil), should.Equal, SegmentCountErr)
	this.So(this.decoder.Decode("111.222", nil), should.Equal, SegmentCountErr)
	this.So(this.decoder.Decode("111.222.333", nil), should.NotEqual, SegmentCountErr)
	this.So(this.decoder.Decode("111.222.333.444", nil), should.Equal, SegmentCountErr) // FUTURE HS384 ?
}

func (this *DecoderFixture) generateTokenWithGoodSignature(secret []byte) string {
	encoder := NewEncoder(WithEncoderAlgorithm(HS256{}), WithEncoderSecret("id", secret))
	token, _ := encoder.Encode(rfcExample{
		Issuer:     "joe",
		Expiration: this.expiration,
	})
	return token
}

func (this *DecoderFixture) TestDecodeInvalidWellFormedSignature() {
	secret := []byte("secret")
	token := this.generateTokenWithBadSignature(secret)

	var claims parsedPayload
	err := this.decoder.Decode(token, &claims)

	this.So(err, should.Equal, UnrecognizedSignatureErr)
	this.So(claims.Expiration, should.Equal, 0)
	this.So(claims.Issuer, should.BeBlank)
}

func (this *DecoderFixture) generateTokenWithBadSignature(secret []byte) string {
	token := this.generateTokenWithGoodSignature(secret)
	parsedToken := strings.Split(token, ".")
	parsedToken[2] = base64.RawURLEncoding.EncodeToString(HS256{}.ComputeHash([]byte("badToken"), secret))
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
	this.encoder = NewEncoder(WithEncoderAlgorithm(HS256{}), WithEncoderSecret("kid", nil))
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

func (this *DecoderFixture) encodeTokenWithoutKID() string {
	encoder := NewEncoder(WithEncoderAlgorithm(HS256{}), WithEncoderSecret("", nil))
	token, _ := encoder.Encode(rfcExample{
		Issuer:     "joe",
		Expiration: 1300819380,
	})
	return token
}

func (this *DecoderFixture) TestValidationResultReturnedAfterDecoding() {
	this.validationErr = errors.New("Validation Result")
	token := this.generateTokenWithGoodSignature([]byte("secret"))
	var parsed parsedPayload
	err := this.decoder.Decode(token, &parsed)
	this.So(err, should.Equal, this.validationErr)
	this.So(this.validatedClaims, should.Equal, &parsed)
}

func (this *DecoderFixture) TestValidationFailsForTokenWithUnexpectedAlgorithm() {
	token := this.generateTokenWithHS512Algorithm()
	var parsed parsedPayload
	err := this.decoder.Decode(token, &parsed)
	this.So(err, should.NotBeNil)
}

func (this *DecoderFixture) generateTokenWithHS512Algorithm() string {
	encoder := NewEncoder(WithEncoderAlgorithm(HS512{}), WithEncoderSecret("id", []byte("secret")))
	token, _ := encoder.Encode(rfcExample{})
	return token
}

type parsedPayload struct {
	Issuer     string `json:"iss"`
	Expiration int64  `json:"exp"`
}
