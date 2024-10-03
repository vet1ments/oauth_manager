package manager

import (
	"github.com/redis/go-redis/v9"
	"time"
)

type RedisBackend interface {
	getConnection() *redis.Conn
}

type options struct {
	redisBackend       RedisBackend
	accessTokenExpire  time.Duration
	refreshTokenExpire time.Duration
}

var (
	defaultOptions = &options{
		accessTokenExpire:  time.Hour * 6,
		refreshTokenExpire: time.Hour * 24 * 15,
	}
)

type Option func(*options)

func apply(opts []Option) *options {
	optCopy := &options{}
	*optCopy = *defaultOptions
	for _, o := range opts {
		o(optCopy)
	}
	return optCopy
}

func WithRedisBackend(backend *RedisBackend) Option {
	return func(o *options) {
		o.redisBackend = *backend
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
