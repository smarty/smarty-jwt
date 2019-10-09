package jwt

// TODO use []permissions instead of scope?
func ParseScope(claims map[string]interface{}, data interface{}) {
	scope, ok := data.(Scope)
	if !ok {
		return
	}

	if value, ok := claims["scope"].(string); ok {
		scope.SetScope(value)
	}
}
