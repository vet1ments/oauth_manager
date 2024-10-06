package token

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"time"
)

type Manager[T any] struct {
	opts options
}

func CreateUserTokenManager[Payload any](opts []Option) *Manager[Payload] {
	o := apply(opts)
	return &Manager[Payload]{
		opts: *o,
	}
}

func (m *Manager[T]) unmarshalTokenData(unmarshalTokenData string) (*TokenData[T], error) {
	td := &TokenData[T]{}
	err := json.Unmarshal([]byte(unmarshalTokenData), td)
	if err != nil {
		return nil, errorWrap(err)
	}
	return td, nil
}

func (m *Manager[T]) createToken(ctx context.Context, userId string, tokenData *TokenData[T], expiresIn time.Duration) (string, error) {
	saveValue, err := json.Marshal(tokenData)
	if err != nil {
		return "", errorWrap(err)
	}
	tokenString, err := m.opts.backend.saveUserToken(ctx, userId, m.opts.tokenCreator.GenerateToken, string(saveValue), expiresIn)
	if err != nil {
		return "", errorWrap(err)
	}
	return tokenString, nil
}

func (m *Manager[T]) CreateAccessToken(ctx context.Context, userId string, payload *T, tokenId ...string) (string, error) {
	tokenUUID := uuid.New()
	_tokenId := tokenUUID.String()
	if len(tokenId) != 0 {
		_tokenId = tokenId[0]
	}
	createdAt, _ := tokenUUID.Time().UnixTime()
	r, e := m.createToken(ctx, userId, &TokenData[T]{
		ID:        _tokenId,
		UserID:    userId,
		Type:      TokenTypeAccess,
		Payload:   *payload,
		CreatedAt: createdAt,
	}, m.opts.accessTokenExpire)
	return r, errorWrap(e)
}

func (m *Manager[T]) CreateRefreshToken(ctx context.Context, userId string, payload *T, tokenId ...string) (string, error) {
	tokenUUID := uuid.New()
	_tokenId := tokenUUID.String()
	if len(tokenId) != 0 {
		_tokenId = tokenId[0]
	}
	createdAt, _ := tokenUUID.Time().UnixTime()

	r, e := m.createToken(ctx, userId, &TokenData[T]{
		ID:        _tokenId,
		UserID:    userId,
		Type:      TokenTypeRefresh,
		Payload:   *payload,
		CreatedAt: createdAt,
	}, m.opts.refreshTokenExpire)

	return r, errorWrap(e)
}

func (m *Manager[T]) CreateTokenPair(ctx context.Context, userId string, payload *T) (*TokenPair, error) {
	tokenUUID := uuid.New()
	tokenId := tokenUUID.String()
	access, err := m.CreateAccessToken(ctx, userId, payload, tokenId)
	if err != nil {
		return nil, errorWrap(err)
	}
	refresh, err := m.CreateRefreshToken(ctx, userId, payload, tokenId)
	if err != nil {
		return nil, errorWrap(err)
	}

	return &TokenPair{
		AccessToken:  access,
		RefreshToken: refresh,
	}, nil
}

// Validate Alias Of GetTokenData
func (m *Manager[T]) Validate(ctx context.Context, tokenString string) (*TokenData[T], error) {
	td, err := m.Validate(ctx, tokenString)
	return td, errorWrap(err)
}
func (m *Manager[T]) GetTokenData(ctx context.Context, tokenString string) (*TokenData[T], error) {
	tokenUnmarshalData, err := m.opts.backend.loadToken(ctx, tokenString)
	if err != nil {
		return nil, errorWrap(err)
	}
	tokenData, err := m.unmarshalTokenData(tokenUnmarshalData)
	if err != nil {
		return nil, errorWrap(err)
	}
	_, err = m.opts.backend.loadUserToken(ctx, tokenData.UserID, tokenString)
	if err != nil {
		return nil, errorWrap(err)
	}
	return tokenData, nil
}

func (m *Manager[T]) RefreshToken(ctx context.Context, refreshTokenString string) (*TokenPair, error) {
	refreshTokenUnmarshalData, err := m.opts.backend.loadToken(ctx, refreshTokenString)
	if err != nil {
		return nil, errorWrap(err)
	}

	refreshTkData, err := m.unmarshalTokenData(refreshTokenUnmarshalData)
	if err != nil {
		return nil, errorWrap(err)
	}

	if refreshTkData.Type != TokenTypeRefresh {
		return nil, ErrInvalidTokenType
	}

	err = m.opts.backend.deleteUserToken(ctx, refreshTkData.UserID, refreshTokenString)
	if err != nil {
		return nil, errorWrap(err)
	}

	userTokenList, err := m.opts.backend.loadUserTokenList(context.Background(), refreshTkData.UserID)
	if err != nil {
		return nil, errorWrap(err)
	}
	tkData := &TokenData[T]{}
	for _, userToken := range userTokenList {
		tokenString := userToken.Token
		tokenUnmarshalData := userToken.Data

		err = json.Unmarshal([]byte(tokenUnmarshalData), tkData)
		if err != nil {
			continue
		}
		if tokenString == refreshTokenString {
			continue
		}
		if tkData.Type != TokenTypeAccess {
			continue
		}

		err = m.opts.backend.deleteUserToken(ctx, tkData.UserID, tokenString)
		if err != nil {
			return nil, errorWrap(err)
		}

		tp, e := m.CreateTokenPair(ctx, tkData.UserID, &tkData.Payload)
		return tp, errorWrap(e)
	}
	return nil, ErrInvalidToken
}

func (m *Manager[T]) AbortToken(ctx context.Context, tokenString string) error {
	return errorWrap(m.opts.backend.deleteToken(ctx, tokenString))
}

func (m *Manager[T]) AbortRefreshToken(ctx context.Context, tokenString string) error {
	td, err := m.GetTokenData(ctx, tokenString)
	if err != nil {
		return errorWrap(err)
	}

	userId := td.UserID
	refreshTokenId := td.ID

	userTokens, err := m.opts.backend.loadUserTokenList(ctx, userId)
	if err != nil {
		return errorWrap(err)
	}

	tokenStringForDelete := make([]string, 0)
	for _, userToken := range userTokens {
		_tokenString := userToken.Token
		_tokenUnmarshalData := userToken.Data
		td, err = m.unmarshalTokenData(_tokenUnmarshalData)
		if err != nil {
			return errorWrap(err)
		}

		if refreshTokenId == td.ID {
			tokenStringForDelete = append(tokenStringForDelete, _tokenString)
		}
	}
	_ = m.opts.backend.deleteUserToken(ctx, userId, tokenStringForDelete...)
	return nil
}
