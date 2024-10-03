package opaquetoken

type Type = int

const (
	AccessTokenType Type = iota + 1
	RefreshTokenType
)

type Token[T any] struct {
	Type    Type
	Payload T
	With    string
}
