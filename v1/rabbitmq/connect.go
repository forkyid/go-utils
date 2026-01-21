package rabbitmq

import (
	"fmt"
	"os"
	"sync"

	"github.com/forkyid/go-utils/v1/logger"
	"github.com/streadway/amqp"
)

var conn *amqp.Connection
var channel *amqp.Channel

func Start(m *sync.Mutex) (*amqp.Channel, error) {
	m.Lock()
	defer m.Unlock()

	var err error
	if conn == nil {
		if os.Getenv("RABBITMQ_PORT") == "" {
			os.Setenv("RABBITMQ_PORT", "5672")
		}

		connString := fmt.Sprintf("amqp://%s:%s@%s:%s",
			os.Getenv("RABBITMQ_USER"),
			os.Getenv("RABBITMQ_PASSWORD"),
			os.Getenv("RABBITMQ_HOST"),
			os.Getenv("RABBITMQ_PORT"),
		)

		conn, err = amqp.Dial(connString)
		if err != nil {
			logger.Errorf(nil, "amqp: dial", err)
			conn = nil
			return nil, err
		}

		go func() {
			errChan := conn.NotifyClose(make(chan *amqp.Error))
			for {
				if <-errChan != nil {
					err = <-errChan
					logger.Errorf(nil, "amqp: connection notify close", err)
					conn = nil
					return
				}
			}
		}()

		logger.Infof("Successfully dialed connection to RabbitMQ.")
	}

	if channel == nil {
		channel, err = conn.Channel()
		if err != nil {
			logger.Errorf(nil, "amqp: connection channel", err)
			conn = nil
			channel = nil
			return nil, err
		}

		go func() {
			errChan := channel.NotifyClose(make(chan *amqp.Error))
			for {
				if <-errChan != nil {
					err = <-errChan
					logger.Errorf(nil, "amqp: channel notify close", err)
					conn = nil
					channel = nil
					return
				}
			}
		}()

		logger.Infof("Successfully opened channel to RabbitMQ.")
	}

	return channel, err
}
