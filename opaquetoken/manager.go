package opaquetoken

import (
	"encoding/json"
	"time"
)

type Manager[T any] struct {
	opts options
}

func CreateManager[T any](opts ...Option) *Manager[T] {
	o := apply(opts)
	return &Manager[T]{
		opts: *o,
	}
}

func (m *Manager[T]) createToken(payload T, tokenType Type, expires time.Duration) (string, error) {
	data, err := json.Marshal(&Token[T]{
		Type:    tokenType,
		Payload: payload,
	})
	if err != nil {
		return "", err
	}

	var token string
	err = m.opts.backend.SaveFunc(func() string {
		token = generateURLSafeOpaqueToken(48)
		return token
	}, data, expires)

	if err != nil {
		return "", err
	}
	return token, nil
}

func (m *Manager[T]) CreateAccessToken(payload T) (string, error) {
	token, err := m.createToken(payload, AccessTokenType, m.opts.accessTokenExpire)
	if err != nil {
		return "", err
	}
	return token, nil
}
func (m *Manager[T]) CreateRefreshToken(payload T) (string, error) {
	token, err := m.createToken(payload, RefreshTokenType, m.opts.refreshTokenExpire)
	if err != nil {
		return "", err
	}
	return token, nil
}

func (m *Manager[T]) LoadToken(tokenString string) (*Token[T], error) {
	tokenByte, err := m.opts.backend.LoadFunc(tokenString)
	if err != nil {
		return nil, err
	}
	tokenData := &Token[T]{}
	err = json.Unmarshal(tokenByte, tokenData)
	if err != nil {
		return nil, err
	}
	return tokenData, nil

}
func (m *Manager[T]) LoadAccessToken(tokenString string) (*Token[T], error) {
	token, err := m.LoadToken(tokenString)
	if err != nil {
		return nil, err
	}
	if token.Type != AccessTokenType {
		return nil, ErrInvalidTokenType
	}
	return token, nil
}

func (m *Manager[T]) LoadRefreshToken(tokenString string) (*Token[T], error) {
	token, err := m.LoadToken(tokenString)
	if err != nil {
		return nil, err
	}
	if token.Type != RefreshTokenType {
		return nil, ErrInvalidTokenType
	}
	return token, nil
}

func (m *Manager[T]) DeleteToken(tokenString string) (*Token[T], error) {
	tk, err := m.LoadToken(tokenString)
	if err != nil {
		return nil, err
	}
	err = m.opts.backend.DeleteFunc(tokenString)
	if err != nil {
		return nil, err
	}
	return tk, nil
}
