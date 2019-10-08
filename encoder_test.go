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
	encoder *Encoder
}

func (this *EncoderFixture) Setup() {
	this.encoder = NewEncoder(this)
}

func (this *EncoderFixture) TestEncode() {
	token := this.encoder.Encode(rfcExample{
		Issuer:     "joe",
		Expiration: 1300819380,
		IsRoot:     true,
	})

	this.So(token, should.Equal, ""+
		"eyJhbGciOiJub25lIn0."+
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.")

	//eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzbWFydHlzdHJlZXRzIiwiZXhwIjoxMjM0NTY3ODl9.4bMJS7-js_HuWLxyLVXRhnVAV3ax2Ey2v6D6HY0Nz4A
}

func (this *EncoderFixture) Serialize(claims interface{}) []byte {
	payload, _ := json.Marshal(claims)
	return bytes.ReplaceAll(payload, []byte(","), []byte(",\r\n "))
}
