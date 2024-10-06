package main

import (
	"context"
	"fmt"
	"github.com/redis/go-redis/v9"
	"github.com/vet1ments/oauth_manager"
	"time"
)

type TokenPayload struct {
	Name string `json:"name"`
}

var TokenContainer = make(map[string][]byte)
var names = []string{
	"test",
	"test2",
}

const UserID = "28f9d61a-8087-4ed9-adfd-bb14d8c91e79"

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	rdOpt := redis.Options{
		Addr: "127.0.0.1:6379",
	}

	cli := redis.NewClient(&rdOpt)
	r, e := cli.Ping(ctx).Result()
	if e != nil {
		panic(e)
	}

	fmt.Println(r)

	options := []oauth_manager.Option{
		oauth_manager.WithOpaqueToken(),
		oauth_manager.WithRedisBackend(cli),
	}

	tkm := oauth_manager.CreateUserTokenManager[TokenPayload](options)

	p, e := tkm.CreateTokenPair(ctx, UserID, &TokenPayload{
		Name: "test",
	})
	if e != nil {
		fmt.Println(e)
		return
	}
	fmt.Println(p.RefreshToken)
}
