package jwt

type DecoderOption func(*Decoder)

func WithNamedDecodingAlgorithms(names ...string) DecoderOption {
	return func(this *Decoder) {
		for _, name := range names {
			algorithm := translateNamedAlgorithm(name)
			WithDecodingAlgorithm(algorithm)(this)
		}
	}
}
func WithDecodingAlgorithm(algorithm Algorithm) DecoderOption {
	return func(this *Decoder) {
		this.algorithms[algorithm.Name()] = algorithm
	}
}
func WithDecodingSecrets(callback func(id string) (secret []byte)) DecoderOption {
	return func(this *Decoder) {
		this.secret = callback
	}
}
func WithDecodingValidator(validator Validator) DecoderOption {
	return func(this *Decoder) {
		this.validators = append(this.validators, validator)
	}
}

func noSecret(_ string) []byte {
	return nil
}

type EncoderOption func(encoder *Encoder)

func WithNamedEncodingAlgorithm(algorithm string) EncoderOption {
	return func(this *Encoder) {
		this.headers.Algorithm = algorithm
		this.algorithm = translateNamedAlgorithm(algorithm)
	}
}
func WithEncodingAlgorithm(algorithm Algorithm) EncoderOption {
	return func(this *Encoder) {
		this.headers.Algorithm = algorithm.Name()
		this.algorithm = algorithm
	}
}
func WithEncodingSecret(id string, secret []byte) EncoderOption {
	return func(this *Encoder) {
		this.headers.KeyID = id
		this.secret = secret
	}
}
