package main

import (
	"context"

	"github.com/redis/go-redis/v9"
)

func NewClient() (*envHandler, error) {
	var opt, _ = redis.ParseURL("redis://default:245965b7fcd047c59d1311fcbf88d776@usw1-emerging-rooster-34385.upstash.io:34385")
	var client = redis.NewClient(opt)

	if err := client.Ping(context.TODO()).Err(); err != nil {
		return nil, err
	}

	var env = &envHandler{
		ctx:   context.Background(),
		redis: client,
	}

	return env, nil
}
