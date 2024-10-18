package v1

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"time"

	connection "github.com/forkyid/go-utils/v1/nsq"
)

const (
	PubTypeNSQD  = "nsqd"
	PubTypeHTTPS = "https"
	retry        = 3
)

func Publish(data []byte) (err error) {
	publishType := os.Getenv("NSQD_PUB_TYPE")
	topic := os.Getenv("NSQD_TOPIC")

	switch publishType {
	case PubTypeHTTPS:
		err = pubTypeHTTPS(topic, data)
	default:
		err = pubTypeNSQD(topic, data)
	}
	return
}

func pubTypeNSQD(topic string, data []byte) (err error) {
	producer, err := connection.Start()
	if err != nil {
		log.Println("failed to connect to nsqd: ", err.Error())
		return
	}

	err = producer.PublishAsync(topic, data, nil)
	if err != nil {
		log.Println("failed to publish data to nsqd: ", err.Error())
		return
	}
	return
}

func pubTypeHTTPS(topic string, data []byte) (err error) {
	pubPool := connection.StartProducerPool()
	ctx := context.Background()
	err = pubPool.Acquire(ctx, 1)
	if err != nil {
		return
	}
	go func() {
		defer pubPool.Release(1)
		publishHTTPS(data, topic)
	}()
	return
}

func backoff(retries int) time.Duration {
	return time.Duration(math.Pow(2, float64(retries))) * time.Second
}

func drainBody(resp *http.Response) {
	if resp.Body != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

func publishHTTPS(data []byte, topic string) {
	host := fmt.Sprintf("%s/pub?topic=%s", os.Getenv("NSQD_HOST"), topic)
	client := &http.Client{}
	req, _ := http.NewRequest(
		http.MethodPost,
		host,
		bytes.NewReader(data),
	)

	for pubRetry := 0; pubRetry <= retry; pubRetry++ {
		resp, err := client.Do(req)
		if err != nil {
			if pubRetry >= retry {
				log.Printf("[ERROR] [NSQD] [%s] [%s] %v \n", host, err.Error(), string(data))
				return
			}
			time.Sleep(backoff(pubRetry))
			continue
		}

		if resp.StatusCode != http.StatusOK {
			drainBody(resp)
			if pubRetry >= retry {
				log.Printf("[ERROR] [NSQD] [Code: %d] [%s] %v\n", resp.StatusCode, host, string(data))
				return
			}
			time.Sleep(backoff(pubRetry))
			continue
		}

		drainBody(resp)
		break
	}
}
