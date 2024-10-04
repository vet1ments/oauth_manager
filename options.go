package oauth_manager

import (
	"github.com/redis/go-redis/v9"
	"time"
)

type options struct {
	accessTokenExpire  time.Duration
	refreshTokenExpire time.Duration
	backend            backend
	tokenCreator       TokenCreator
}

var (
	defaultOptions = &options{
		accessTokenExpire:  time.Hour * 6,
		refreshTokenExpire: time.Hour * 24 * 15,
		tokenCreator:       &OpaqueTokenCreator{},
	}
)

type Option func(*options)

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

func WithOpaqueToken() Option {
	return func(o *options) {
		o.tokenCreator = &OpaqueTokenCreator{}

	}
}

func WithRedisBackend(client *redis.Client) Option {
	return func(o *options) {
		o.backend = &RedisBackend{
			client: client,
		}
	}
}

func apply(opts []Option) *options {
	optCopy := &options{}
	*optCopy = *defaultOptions
	for _, o := range opts {
		o(optCopy)
	}
	return optCopy
}
