package jwt

func ParseAudience(claims map[string]interface{}, data interface{}) {
	audience, ok := data.(Audience)
	if !ok {
		return
	}

	if value, ok := claims["aud"].(string); ok {
		audience.SetAudience(value)
	}
}
