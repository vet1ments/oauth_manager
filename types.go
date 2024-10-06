package tokenmanager

import "time"

type Type = int

const (
	TypeAccess Type = iota + 1
	TypeRefresh
)

type TokenData[T any] struct {
	ID        string        `json:"id"`
	UserID    string        `json:"user_id"`
	Type      Type          `json:"type"`
	Payload   T             `json:"payload"`
	CreatedAt int64         `json:"created_at"`
	ExpiresIn time.Duration `json:"expires_in"`
}
