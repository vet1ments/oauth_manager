package oauth_manager

type tokenCreator interface {
	GenerateToken() (string, error)
}

type opaqueTokenCreator struct{}

func (o *opaqueTokenCreator) GenerateToken() (string, error) {
	return generateURLSafeOpaqueToken(48), nil
}

type jwtTokenCreator struct{}

func (o *jwtTokenCreator) GenerateToken() (string, error) {
	return generateURLSafeOpaqueToken(48), nil
}
