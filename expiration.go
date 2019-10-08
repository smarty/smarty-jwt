package jwt

func ParseExpiration(claims map[string]interface{}, data interface{}) {
	expiration, ok := data.(Expiration)
	if !ok {
		return
	}

	if value, ok := claims["exp"].(int); ok {
		expiration.SetExpiration(int64(value))
	}
}
