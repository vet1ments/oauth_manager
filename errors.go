package token

import "errors"

var (
	ErrTokenNotFound = errors.New("ErrTokenNotFound")
)

var (
	ErrInvalidTokenType = errors.New("Invalid token type")
	ErrInvalidToken     = errors.New("Invalid token")
)
