package client

import (
	"context"

	"github.com/redis/go-redis/v9"
)

func NewRedisClient(url string) (*redis.Client, error) {
	var opt, _ = redis.ParseURL(url)
	var client = redis.NewClient(opt)

	if err := client.Ping(context.TODO()).Err(); err != nil {
		return nil, err
	}

	return client, nil
}
