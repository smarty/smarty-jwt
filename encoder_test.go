package jwt

import (
	"bytes"
	"encoding/json"
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
	encoder := NewEncoder(Algorithm("none"), serializer(this))
	token := encoder.Encode(rfcExample{
		Issuer:     "joe",
		Expiration: 1300819380,
		IsRoot:     true,
	})

	this.So(token, should.Equal, ""+
		"eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.")

	//eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzbWFydHlzdHJlZXRzIiwiZXhwIjoxMjM0NTY3ODl9.4bMJS7-js_HuWLxyLVXRhnVAV3ax2Ey2v6D6HY0Nz4A
}

func (this *EncoderFixture) TestEncodeWithSignature() {
	encoder := NewEncoder(Secret([]byte("secret")), Algorithm("HS256"))
	token := encoder.Encode(rfcExample{
		Issuer:     "joe",
		Expiration: 1300819380,
		IsRoot:     true,
	})

	this.So(token, should.Equal, "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.AnVDMBnOG4Jawuf5G3HjePSk-ux9fVk4UCuXVi6hrA4")
}

func (this *EncoderFixture) Serialize(claims interface{}) []byte {
	payload, _ := json.Marshal(claims)
	return bytes.ReplaceAll(payload, []byte(","), []byte(",\r\n "))
}
