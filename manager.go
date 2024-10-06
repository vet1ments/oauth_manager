package tokenmanager

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"time"
)

func newTokenID() string { return uuid.New().String() }

type UserTokenInfoM[T any] struct {
	TokenData   *TokenData[T]
	TokenString string
}

type UserTokenInfoPairM[T any] struct {
	AccessToken  *UserTokenInfoM[T]
	RefreshToken *UserTokenInfoM[T]
}

type user[T any] struct {
	opts options
}

func (u *user[T]) NewTokenID() string {
	return newTokenID()
}

func (u *user[T]) createToken(ctx context.Context, userId string, tokenData *TokenData[T], expiresIn time.Duration) (*UserTokenInfoM[T], error) {
	saveValue, err := json.Marshal(tokenData)
	if err != nil {
		return nil, errorWrap(err)
	}
	tokenString, err := u.opts.backend.saveUserToken(ctx, userId, u.opts.tokenCreator.GenerateToken, string(saveValue), expiresIn)
	if err != nil {
		return nil, errorWrap(err)
	}

	return &UserTokenInfoM[T]{
		TokenData:   tokenData,
		TokenString: tokenString,
	}, nil
}

func (u *user[T]) CreateAccessToken(ctx context.Context, userId string, payload *T, tokenId ...string) (*UserTokenInfoM[T], error) {
	tokenUUID := uuid.New()
	_tokenId := tokenUUID.String()
	if len(tokenId) != 0 {
		_tokenId = tokenId[0]
	}
	createdAt, _ := tokenUUID.Time().UnixTime()
	r, e := u.createToken(ctx, userId, &TokenData[T]{
		ID:        _tokenId,
		UserID:    userId,
		Type:      TypeAccess,
		Payload:   *payload,
		CreatedAt: createdAt,
		ExpiresIn: u.opts.accessTokenExpire,
	}, u.opts.accessTokenExpire)
	return r, errorWrap(e)
}

func (u *user[T]) CreateRefreshToken(ctx context.Context, userId string, payload *T, tokenId ...string) (*UserTokenInfoM[T], error) {
	tokenUUID := uuid.New()
	_tokenId := tokenUUID.String()
	if len(tokenId) != 0 {
		_tokenId = tokenId[0]
	}
	createdAt, _ := tokenUUID.Time().UnixTime()

	r, e := u.createToken(ctx, userId, &TokenData[T]{
		ID:        _tokenId,
		UserID:    userId,
		Type:      TypeRefresh,
		Payload:   *payload,
		CreatedAt: createdAt,
		ExpiresIn: u.opts.refreshTokenExpire,
	}, u.opts.refreshTokenExpire)

	return r, errorWrap(e)
}

func (u *user[T]) CreateTokenPair(ctx context.Context, userId string, payload *T) (*UserTokenInfoPairM[T], error) {
	tid := u.NewTokenID()

	access, err := u.CreateAccessToken(ctx, userId, payload, tid)
	if err != nil {
		return nil, errorWrap(err)
	}

	refresh, err := u.CreateRefreshToken(ctx, userId, payload, tid)
	if err != nil {
		return nil, errorWrap(err)
	}
	g := &UserTokenInfoPairM[T]{
		AccessToken:  access,
		RefreshToken: refresh,
	}

	return g, nil
}

func (u *user[T]) LoadToken(ctx context.Context, userId string, tokenString string) (*UserTokenInfoM[T], error) {
	userToken, err := u.opts.backend.loadUserToken(ctx, userId, tokenString)
	if err != nil {
		return nil, errorWrap(err)
	}
	tokenData := &TokenData[T]{}
	err = json.Unmarshal([]byte(userToken.TokenData), tokenData)
	if err != nil {
		return nil, errorWrap(err)
	}
	return &UserTokenInfoM[T]{
		TokenData:   tokenData,
		TokenString: userToken.TokenString,
	}, nil
}

func (u *user[T]) LoadTokenList(ctx context.Context, userId string) ([]*UserTokenInfoM[T], error) {
	tokenList, err := u.opts.backend.loadUserTokenList(ctx, userId)
	if err != nil {
		return nil, errorWrap(err)
	}
	userTokenList := make([]*UserTokenInfoM[T], 0)
	for _, token := range tokenList {
		v := &TokenData[T]{}
		err := json.Unmarshal([]byte(token.TokenData), v)
		if err != nil {
			continue
		}
		userTokenList = append(userTokenList, &UserTokenInfoM[T]{
			TokenData:   v,
			TokenString: token.TokenString,
		})
	}
	return userTokenList, nil
}

type Manager[T any] struct {
	opts options
	User *user[T]
}

func CreateManager[Payload any](opts []Option) *Manager[Payload] {
	o := apply(opts)

	m := &Manager[Payload]{
		opts: *o,
		User: &user[Payload]{
			opts: *o,
		},
	}
	return m
}

func (m *Manager[T]) unmarshalTokenData(unmarshalTokenData string) (*TokenData[T], error) {
	td := &TokenData[T]{}
	err := json.Unmarshal([]byte(unmarshalTokenData), td)
	if err != nil {
		return nil, errorWrap(err)
	}
	return td, nil
}

func (m *Manager[T]) NewTokenID() string {
	return newTokenID()
}

// Validate Alias Of GetTokenData
func (m *Manager[T]) Validate(ctx context.Context, tokenString string) (*TokenData[T], error) {
	td, err := m.GetTokenData(ctx, tokenString)
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
	return tokenData, nil
}

func (m *Manager[T]) AbortToken(ctx context.Context, tokenString string) error {
	return errorWrap(m.opts.backend.deleteToken(ctx, tokenString))
}

type RefreshTokenOption struct {
	Duration time.Duration
}

func (m *Manager[T]) RefreshToken(ctx context.Context, tokenString string, option *RefreshTokenOption, newPayload ...*T) (*UserTokenInfoPairM[T], error) {
	refreshTokenData, err := m.GetTokenData(ctx, tokenString)
	if err != nil {
		return nil, errorWrap(err)
	}
	userRefreshTokenInfo, err := m.User.LoadToken(ctx, refreshTokenData.UserID, tokenString)
	if err != nil {
		return nil, errorWrap(err)
	}
	refreshTokenData = userRefreshTokenInfo.TokenData

	if refreshTokenData.Type != TypeRefresh {
		return nil, ErrInvalidTokenType
	}

	userId := refreshTokenData.UserID
	payload := &refreshTokenData.Payload
	if len(newPayload) != 0 {
		payload = newPayload[0]
	}

	var refreshTokenInfo *UserTokenInfoM[T]
	if time.Now().UTC().Sub(time.Unix(refreshTokenData.CreatedAt, 0)) <= option.Duration {
		refreshTokenInfo, err = m.User.CreateRefreshToken(ctx, userId, payload)
		if err != nil {
			return nil, errorWrap(err)
		}
	} else {
		refreshTokenInfo = userRefreshTokenInfo
	}

	accessTokenInfo, err := m.User.CreateAccessToken(ctx, userId, payload, refreshTokenInfo.TokenData.ID)
	if err != nil {
		return nil, errorWrap(err)
	}

	return &UserTokenInfoPairM[T]{
		AccessToken:  accessTokenInfo,
		RefreshToken: refreshTokenInfo,
	}, nil
}
