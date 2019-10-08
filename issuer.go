package jwt

func ParseIssuer(claims map[string]interface{}, data interface{}) {
	issuer, ok := data.(Issuer)
	if !ok {
		return
	}

	if value, ok := claims["iss"].(string); ok {
		issuer.SetIssuer(value)
	}
}
