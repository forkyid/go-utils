package nsq

import (
	"log"
	"os"
	"strconv"

	"github.com/nsqio/go-nsq"
	"golang.org/x/sync/semaphore"
)

type nopLogger struct{}

var (
	producer *nsq.Producer
	pool     *semaphore.Weighted
)

func (*nopLogger) Output(int, string) error {
	return nil
}

func Start() (*nsq.Producer, error) {
	if producer == nil || producer.Ping() != nil {
		config := nsq.NewConfig()
		config.Set("heartbeat_interval", "10s")

		var err error
		producer, err = nsq.NewProducer(os.Getenv("NSQD_HOST"), config)
		if err != nil {
			log.Println("failed to connect to nsqd: ", err.Error())
			return nil, err
		}

		producer.SetLogger(&nopLogger{}, 0)
	}
	return producer, nil
}

func StartProducerPool() *semaphore.Weighted {
	if pool == nil {
		poolSize, _ := strconv.Atoi(os.Getenv("NSQD_POOL_SIZE"))
		pool = semaphore.NewWeighted(int64(poolSize))
	}
	return pool
}
