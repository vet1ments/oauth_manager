package oauth_manager

import (
	"context"
	"time"
)

type TokenType = int

const (
	TokenTypeAccess TokenType = iota + 1
	TokenTypeRefresh
)

type backend interface {
	saveToken(ctx context.Context, token string, value interface{}, expire time.Duration) (bool, error)
	loadToken(ctx context.Context, token string) (string, error)
	deleteToken(ctx context.Context, tokens ...string) error
	getTokenInfo(ctx context.Context, token string) (*BackendTokenInfo, error)
	isTokenExist(ctx context.Context, token string) (bool, error)

	cleanupUserToken(ctx context.Context, userId string) error
	saveUserToken(ctx context.Context, userId string, genToken func() (string, error), value interface{}, expiresIn time.Duration) (string, error)
	loadUserToken(ctx context.Context, userId string, tokenString string) (*UserToken, error)
	loadUserTokenList(ctx context.Context, userId string) ([]*UserToken, error)
	deleteUserToken(ctx context.Context, userId string, tokens ...string) error
}

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
