package jwt

func ParseExpiration(claims map[string]interface{}, data interface{}) {
	expiration, ok := data.(Expiration)
	if !ok {
		return
	}

	switch value := claims["exp"].(type) {
	case float64:
		expiration.SetExpiration(int64(value))
	case int:
		expiration.SetExpiration(int64(value))
	}
}
