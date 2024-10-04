package oauth_manager

import "time"

type TokenType = int

const (
	TokenTypeAccess TokenType = iota + 1
	TokenTypeRefresh
)

type BackendTokenInfo struct {
	TokenString string
	TokenData   string
	ExpiresIn   time.Duration
}

type TokenData[T any] struct {
	ID        string
	UserID    string
	Type      TokenType
	Payload   T
	CreatedAt int64
}

type TokenPair struct {
	AccessToken  string
	RefreshToken string
}

type UserToken struct {
	Token string // literal Token String
	Data  string // unmarshal token data
}
