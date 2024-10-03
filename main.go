package main

import (
	"errors"
	"fmt"
	"github.com/vet1ments/oauth_manager/opaquetoken"
	"time"
)

type TokenPayload struct {
	Name string `json:"name"`
}

var TokenContainer = make(map[string][]byte)
var names = []string{
	"노홍석",
	"호라굴",
}

func main() {

	s := opaquetoken.CreateManager[*TokenPayload](
		opaquetoken.WithBackend(&opaquetoken.Backend{
			SaveFunc: func(genToken func() string, value []byte, expires time.Duration) error {
				for {
					tokenString := genToken()
					if _, ok := TokenContainer[tokenString]; ok {
						continue
					} else {
						TokenContainer[tokenString] = value
						break
					}
				}
				return nil
			},
			LoadFunc: func(tokenString string) ([]byte, error) {
				if _, ok := TokenContainer[tokenString]; ok {
					return TokenContainer[tokenString], opaquetoken.ErrInvalidToken
				}
				return nil, opaquetoken.ErrInvalidToken
			},
		}),
	)

	for _, name := range names {
		payload := &TokenPayload{
			Name: name,
		}
		tokenString, err := s.CreateAccessToken(payload)

		if err != nil {
			fmt.Println(err)
		}
		t, err := s.LoadAccessToken(tokenString)
		if err != nil {
			fmt.Println(errors.Is(err, opaquetoken.ErrInvalidToken))
			fmt.Println(err)
			return
		}
		fmt.Println(t.Type, t.Payload.Name)
	}

}
