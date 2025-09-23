package cache

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"time"

	"github.com/go-redis/redis"
	"github.com/pkg/errors"
)

func Get(key string, dur ...time.Duration) (interface{}, error) {
	if !IsCacheConnected() {
		return nil, fmt.Errorf("redis connect failed: %s", os.Getenv("REDIS_HOST"))
	}

	client := getRedisClient()

	resp := client.Get(key)
	if resp.Err() == redis.Nil {
		return nil, nil
	}

	if resp.Err() != nil {
		return nil, errors.Wrap(resp.Err(), "redis get")
	}

	var data interface{}
	err := json.Unmarshal([]byte(resp.Val()), &data)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshal")
	}

	if len(dur) == 1 {
		go SetExpire(key, dur[0])
	}

	return data, nil
}

func GetUnmarshal(key string, target interface{}, dur ...time.Duration) error {
	if reflect.ValueOf(target).Kind() != reflect.Ptr {
		fmt.Println("unmarshal target is not a pointer")
	}
	if !IsCacheConnected() {
		return fmt.Errorf("redis connect failed: %s", os.Getenv("REDIS_HOST"))
	}

	client := getRedisClient()

	resp := client.Get(key)
	if resp.Err() == redis.Nil {
		return resp.Err()
	}

	if resp.Err() != nil {
		return errors.Wrap(resp.Err(), "redis get")
	}

	err := json.Unmarshal([]byte(resp.Val()), target)
	if err != nil {
		return errors.Wrap(err, "unmarshal")
	}

	if len(dur) == 1 {
		go SetExpire(key, dur[0])
	}

	return nil
}

func SetJSON(key string, value interface{}, dur time.Duration) error {
	if !IsCacheConnected() {
		return fmt.Errorf("redis connect failed: %s", os.Getenv("REDIS_HOST"))
	}

	client := getRedisClient()

	valueJSON, err := json.Marshal(value)
	if err != nil {
		return errors.Wrap(err, "marshal failed")
	}

	return errors.Wrap(client.Set(key, valueJSON, dur).Err(), "redis set failed")
}

func IsCacheExists(key string) (bool, error) {
	if !IsCacheConnected() {
		return false, fmt.Errorf("redis connect failed: %s", os.Getenv("REDIS_HOST"))
	}

	client := getRedisClient()
	res := client.Exists(key)
	if res.Err() != nil {
		return false, errors.Wrap(res.Err(), "redis check failed")
	}

	return res.Val() != 0, nil
}

// SetExpire set the expiration time for the key
func SetExpire(key string, dur time.Duration) error {
	if !IsCacheConnected() {
		return fmt.Errorf("redis connect failed: %s", os.Getenv("REDIS_HOST"))
	}
	client := getRedisClient()

	if err := client.Expire(key, dur).Err(); err != nil {
		return errors.Wrap(err, "set expire failed")
	}
	return nil
}

// Delete removes keys
func Delete(key ...string) error {
	if !IsCacheConnected() {
		return fmt.Errorf("redis connect failed: %s", os.Getenv("REDIS_HOST"))
	}

	client := getRedisClient()

	if err := client.Del(key...).Err(); err != nil {
		return errors.Wrap(err, "delete failed")
	}
	return nil
}

// Purge params
// @key: string
// return error
func Purge(key string) error {
	if !IsCacheConnected() {
		return fmt.Errorf("redis connect failed: %s", os.Getenv("REDIS_HOST"))
	}

	client := getRedisClient()

	cursor := client.Scan(0, "*"+key+"*", 0).Iterator()
	err := cursor.Err()
	if err != nil {
		return errors.Wrap(err, "cursor scan failed")
	}

	for cursor.Next() {
		err := client.Del(cursor.Val()).Err()
		if err != nil {
			return errors.Wrap(err, "delete failed")
		}
	}

	return nil
}

// TTL returns the remaining time to live for a key
func TTL(key string) (time.Duration, error) {
	if !IsCacheConnected() {
		return 0, fmt.Errorf("redis connect failed: %s", os.Getenv("REDIS_HOST"))
	}

	client := getRedisClient()

	return client.TTL(key).Result()
}
