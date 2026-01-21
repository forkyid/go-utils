package v1

import (
	"fmt"
	"io"
	"log"
	"time"

	"github.com/useinsider/go-pkg/insrequester"

	connection "github.com/forkyid/go-utils/v1/nsq"
	"github.com/forkyid/go-utils/v1/util/env"
)

const (
	PubTypeNSQD         = "nsqd"
	PubTypeHTTP         = "http"
	defaultRetry        = 3
	defaultBackOffDelay = 2000
	defaultTimeOut      = 5000
)

func Publish(data []byte) (err error) {
	publishType := env.GetStr("NSQD_PUB_TYPE", PubTypeNSQD)
	topic := env.GetStr("NSQD_TOPIC")

	switch publishType {
	case PubTypeHTTP:
		go pubTypeHTTPS(topic, data)
	default:
		err = pubTypeNSQD(topic, data)
	}
	return
}

func pubTypeNSQD(topic string, data []byte) (err error) {
	producer, err := connection.Start()
	if err != nil {
		log.Println("failed to connect to nsqd: ", err.Error())
		return err
	}

	err = producer.PublishAsync(topic, data, nil)
	if err != nil {
		log.Println("failed to publish data to nsqd: ", err.Error())
		return
	}
	return
}

func pubTypeHTTPS(topic string, data []byte) (err error) {
	host := fmt.Sprintf("%s/pub?topic=%s", env.GetStr("NSQD_HOST"), topic)
	requester := insrequester.NewRequester().
		WithRetry(insrequester.RetryConfig{
			WaitBase: time.Duration(env.GetInt("NSQD_BACKOFF_DELAY", defaultBackOffDelay)) * time.Millisecond,
			Times:    env.GetInt("NSQD_RETRY_LIMIT", defaultRetry),
		}).WithTimeout(time.Duration(env.GetInt("NSQD_TIMEOUT", defaultTimeOut)) * time.Millisecond).Load()
	resp, err := requester.Post(insrequester.RequestEntity{
		Endpoint: host,
		Body:     data,
	})
	if err != nil {
		log.Printf("[ERROR] [NSQD] [%s] [%s] %v \n", host, err.Error(), string(data))
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return
}
