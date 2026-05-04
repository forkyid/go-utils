package nsq

import "github.com/forkyid/go-utils/v1/util/env"

type Config struct {
	IsActive bool
	ErrorLog bool
}

var Configs Config

func init() {
	Configs = Config{
		IsActive: env.GetBool("NSQD_ACTIVE", true),
		ErrorLog: env.GetBool("NSQD_ERROR_LOG", true),
	}
}

func (nsq *Config) IsNsqActive() bool {
	return nsq.IsActive
}

func (nsq *Config) ShouldLogErrors() bool {
	return nsq.ErrorLog
}
