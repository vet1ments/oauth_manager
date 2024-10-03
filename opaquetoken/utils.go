package opaquetoken

import (
	"crypto/rand"
	"encoding/base64"
)

func generateURLSafeOpaqueToken(length int) string {
	// 길이에 맞는 바이트 배열 생성
	bytes := make([]byte, length)

	// 랜덤 바이트를 생성
	_, _ = rand.Read(bytes)

	// Base64 URL Safe 인코딩
	token := base64.RawURLEncoding.EncodeToString(bytes)
	return token
}
