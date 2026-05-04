package rest

var Configs config

type config struct {
	SkipErrorStatusCodes map[int]struct{}
}

func init() {
	Configs = config{
		SkipErrorStatusCodes: make(map[int]struct{}),
	}
}

func (c *config) SetSkipErrorStatusCodes(codes ...int) {
	for _, code := range codes {
		c.SkipErrorStatusCodes[code] = struct{}{}
	}
}

func (c *config) SkippedStatusCode(statusCode int) bool {
	_, exists := c.SkipErrorStatusCodes[statusCode]
	return exists
}
