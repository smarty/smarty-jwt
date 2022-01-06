package jwt

func NewEncoder1(options ...encoderOption) Encoder1 {
	var config encoderConfiguration
	EncoderOptions.apply(options...)(&config)
	return nil
}

func (encoderSingleton) Setting(value string) encoderOption {
	return func(this *encoderConfiguration) { this.Route = value }
}

func (encoderSingleton) apply(options ...encoderOption) encoderOption {
	return func(this *encoderConfiguration) {
		for _, item := range EncoderOptions.defaults(options...) {
			item(this)
		}
	}
}
func (encoderSingleton) defaults(options ...encoderOption) []encoderOption {
	return append([]encoderOption{
		EncoderOptions.Setting(""),
	}, options...)
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type encoderConfiguration struct {
	Route string
}
type encoderOption func(*encoderConfiguration)
type encoderSingleton struct{}

var EncoderOptions encoderSingleton
