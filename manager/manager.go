package manager

import (
	"context"
	"fmt"
	"github.com/redis/go-redis/v9"
	"strconv"
	"strings"
	"time"
)

type Manager struct {
	opts options
}

type Type = int

const (
	AccessTokenType Type = iota + 1
	RefreshTokenType
)

func CreateManager(opts ...Option) *Manager {
	o := apply(opts)
	if o.redisBackend == nil {
		panic("redis backend is nil")
	}

	return &Manager{
		opts: *o,
	}
}

func (m *Manager) getConn() *redis.Conn {
	return m.opts.redisBackend.getConnection()
}

func getPrefix(tokenType Type, userId string) string {
	switch tokenType {
	case AccessTokenType:
		return strings.Join([]string{
			"USER_ACCESS_TOKENS",
			userId,
		}, ":")
	case RefreshTokenType:
		return strings.Join([]string{
			"USER_REFRESH_TOKENS",
			userId,
		}, ":")
	default:
		panic("invalid token type")
	}
}

func (m *Manager) SaveToken(tokenType Type, userId, tokenString string) error {
	_ = m.CleanupToken(tokenType, userId)
	conn := m.getConn()
	defer func() {
		err := conn.Close()
		if err != nil {
			fmt.Println("redis close err:", err)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	now := time.Now().UTC()
	switch tokenType {
	case AccessTokenType:
		now.Add(m.opts.accessTokenExpire)
	case RefreshTokenType:
		now.Add(m.opts.refreshTokenExpire)
	}
	err := conn.ZAdd(ctx, getPrefix(tokenType, userId), redis.Z{
		Score:  float64(now.Unix()),
		Member: tokenString,
	}).Err()
	if err != nil {
		return err
	}
	return nil

}
func (m *Manager) LoadToken(tokenType Type, userId string) {
	_ = m.CleanupToken(tokenType, userId)
	conn := m.getConn()
	defer func() {
		err := conn.Close()
		if err != nil {
			fmt.Println("redis close err:", err)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

}
func (m *Manager) DeleteToken(tokenType Type, userId string) {
	_ = m.CleanupToken(tokenType, userId)
	conn := m.getConn()
	defer func() {
		err := conn.Close()
		if err != nil {
			fmt.Println("redis close err:", err)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
}

func (m *Manager) CleanupToken(tokenType Type, userId string) error {
	conn := m.getConn()
	defer func() {
		err := conn.Close()
		if err != nil {
			fmt.Println("redis close err:", err)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	key := getPrefix(tokenType, userId)
	err := conn.ZRemRangeByScore(ctx, key, "0", strconv.FormatInt(time.Now().UTC().Unix(), 10)).Err()
	if err != nil {
		return err
	}
	result, err := conn.ZRange(ctx, key, 0, -1).Result()
	if err != nil {
		return err
	}
	err = conn.Unlink(ctx, result...).Err()
	if err != nil {
		return err
	}
	return nil
}
