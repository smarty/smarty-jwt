package jwt

func NewDecoder1(options ...decoderOption) Decoder1 {
	var config decoderConfiguration
	DecoderOptions.apply(options...)(&config)
	return nil
}

func (decoderSingleton) Setting(value string) decoderOption {
	return func(this *decoderConfiguration) { this.Route = value }
}

func (decoderSingleton) apply(options ...decoderOption) decoderOption {
	return func(this *decoderConfiguration) {
		for _, item := range DecoderOptions.defaults(options...) {
			item(this)
		}
	}
}
func (decoderSingleton) defaults(options ...decoderOption) []decoderOption {
	return append([]decoderOption{
		DecoderOptions.Setting(""),
	}, options...)
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type decoderConfiguration struct {
	Route string
}
type decoderOption func(*decoderConfiguration)
type decoderSingleton struct{}

var DecoderOptions decoderSingleton
