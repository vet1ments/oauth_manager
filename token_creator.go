package oauth_manager

type TokenCreator interface {
	GenerateToken() (string, error)
}

type OpaqueTokenCreator struct{}

func (o *OpaqueTokenCreator) GenerateToken() (string, error) {
	return generateURLSafeOpaqueToken(48), nil
}
