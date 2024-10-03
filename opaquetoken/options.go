package opaquetoken

import (
	"time"
)

type T any

type (
	GenerateTokenFn func() string
)

type (
	SaveFuncType   func(genToken func() string, value []byte, expires time.Duration) error
	LoadFuncType   func(tokenString string) ([]byte, error)
	DeleteFuncType func(tokenString string) error
)

type Backend struct {
	SaveFunc   SaveFuncType
	LoadFunc   LoadFuncType
	DeleteFunc DeleteFuncType
}

var (
	defaultBackend = &Backend{
		SaveFunc: func(genToken func() string, value []byte, expires time.Duration) error {
			return ErrNotImplemented
		},
		LoadFunc: func(tokenString string) ([]byte, error) {
			return nil, ErrNotImplemented
		},
		DeleteFunc: func(tokenString string) error {
			return ErrNotImplemented
		},
	}
	defaultOptions = &options{
		backend:            *defaultBackend,
		accessTokenExpire:  time.Hour * 6,
		refreshTokenExpire: time.Hour * 24 * 15,
	}
)

type options struct {
	backend            Backend
	accessTokenExpire  time.Duration
	refreshTokenExpire time.Duration
}

type Option func(*options)

func apply(opts []Option) *options {
	optCopy := &options{}
	*optCopy = *defaultOptions
	for _, o := range opts {
		o(optCopy)
	}
	return optCopy
}

func WithBackend(backend *Backend) Option {
	return func(o *options) {
		o.backend = *backend
	}
}

func WithAccessTokenExpire(expire time.Duration) Option {
	return func(o *options) {
		o.accessTokenExpire = expire
	}
}

func WithRefreshTokenExpire(expire time.Duration) Option {
	return func(o *options) {
		o.refreshTokenExpire = expire
	}
}
