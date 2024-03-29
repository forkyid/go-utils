package v1

import (
	"fmt"
	"log"
	"sync"

	"github.com/forkyid/go-utils/v1/rabbitmq"
	"github.com/streadway/amqp"
)

// Route type Schema
type Route struct {
	ExchangeName string
	ExchangeType string
	RoutingKey   string
	QueueName    string
}

// Publish type Schema
type Publish struct {
	Headers amqp.Table
	Body    string
}

var m sync.Mutex

// Publish sends message to message broker
func (route *Route) Publish(publish *Publish) error {
	channel, err := rabbitmq.Start(&m)
	if err != nil {
		log.Println(fmt.Sprintf("%s: %s", "Failed to Connect to RabbitMQ", err.Error()))
		return err
	}

	err = channel.ExchangeDeclare(
		route.ExchangeName, // name
		route.ExchangeType, // type
		true,               // durable
		false,              // auto-delete
		false,              // internal
		false,              // no-wait
		nil,                // argument
	)
	if err != nil {
		log.Println(fmt.Sprintf("%s: %s", "Failed to declare an exchange", err.Error()))
		return err
	}

	args := amqp.Table{
		"x-queue-mode": "lazy",
		"x-max-priority": 255,
	}
	_, err = channel.QueueDeclare(
		route.QueueName, // queue name
		true,            // durable
		false,           // delete when used
		false,           // exclusive
		false,           // no-wait
		args,            // arguments
	)
	if err != nil {
		log.Println(fmt.Sprintf("%s: %s", "Failed to declare a queue", err.Error()))
		return err
	}

	err = channel.QueueBind(
		route.QueueName,	// queue name
		route.RoutingKey,	// routing key
		route.ExchangeName, // exchange
		false,				// no-wait
		nil,				// arguments
	)
	if err != nil {
		log.Println(fmt.Sprintf("%s: %s", "Failed to bind a queue", err.Error()))
	}

	err = channel.Publish(
		route.ExchangeName, // exchange name
		route.RoutingKey,   // Routing key
		false,              // mandatory
		false,              // immediate
		amqp.Publishing{
			DeliveryMode: amqp.Persistent,
			ContentType:  "application/json",
			Body:         []byte(publish.Body),
			Headers:      publish.Headers,
		},
	)
	if err != nil {
		log.Println(fmt.Sprintf("%s: %s", "Failed to publish a message", err.Error()))
	}

	return nil
}