# Logger
Logger is an utility logging system based on [Logrus](https://github.com/sirupsen/logrus). This package initialize the logging system on debug level. There are 5 logging levels provided: debug, info, warn, error fatal (sorted by severity). Fields used as the log information are key, service name, params (query parameters), status code, trace (runtime stack information), request (URI), method, IP, remote address, and body (args). Body is an optional fields.

## Log Format Function Usage
`Fatalf` function is used to log very severe error events. Once again, the body args is optional. Example:
```go
// General Example

import (
	httpExample "github.com/forkyid/go-boilerplate/src/entity/v1/http/example"
	"github.com/forkyid/go-boilerplate/src/service/v1/example"
	"github.com/forkyid/go-utils/v1/logger"
	"github.com/gin-gonic/gin"
)

func Create(ctx *gin.Context) {
	req := httpExample.CreateRequest{} // body request struct
	err = example.Create(req) // calling service example Create func
	if err != nil { // catch error
        logger.Fatalf(ctx, "create req", err, req) // fatal logging
		return
	}
}
```
```go
// Database Initialization (Real Case)

DB, err := gorm.Open(postgres.Open(postgresCon), &gorm.Config{
    Logger: logger.Default.LogMode(logger.Info),
})
if err != nil {
    errMsg := fmt.Sprintf("failed to connect %s on %s:%s", dbName, hostType, port)
    logger.Fatalf(nil, errMsg, err)
    panic(errMsg)
}
```

`Errorf` function is used to log issues that preventing the application to properly functioning. How to use this is the same like the genral example of `Fatalf`. Example:
```go
import (
	httpExample "github.com/forkyid/go-boilerplate/src/entity/v1/http/example"
	"github.com/forkyid/go-boilerplate/src/service/v1/example"
	"github.com/forkyid/go-utils/v1/logger"
	"github.com/gin-gonic/gin"
)

func Create(ctx *gin.Context) {
	req := httpExample.CreateRequest{} // body request struct
	err = example.Create(req) // calling service example Create func
	if err != nil { // catch error
        logger.Errorf(ctx, "create req", err, req) // error logging
		return
	}
}
```
You can also use the rest Log function to simplify `Errorf` calls.
```go
import (
	httpExample "github.com/forkyid/go-boilerplate/src/entity/v1/http/example"
	"github.com/forkyid/go-boilerplate/src/service/v1/example"
	"github.com/forkyid/go-utils/v1/logger"
	"github.com/gin-gonic/gin"
)

func Create(ctx *gin.Context) {
	req := httpExample.CreateRequest{} // body request struct
	err = example.Create(req) // calling service example Create func
	if err != nil { // catch error
        rest.ResponseMessage(ctx, http.StatusInternalServerError).Log("create req", err, req) // rest Log will redirect to Errorf
        // Above line is the same as:
        // rest.ResponseMessage(ctx, http.StatusInternalServerError)
        // logger.Errorf(ctx, "create req", err, req)
		return
	}
}
```

`Warnf` function is used to log potentially harmful events. `Warnf` doesn't need gin Context and only log the trace error information. Example:
```go
import (
	httpExample "github.com/forkyid/go-boilerplate/src/entity/v1/http/example"
	"github.com/forkyid/go-boilerplate/src/service/v1/example"
	"github.com/forkyid/go-utils/v1/logger"
	"github.com/gin-gonic/gin"
)

func Create(ctx *gin.Context) {
    req := httpExample.ESCreateRequest{} // body request struct
    err = example.ESCreate(req) // calling service example Elasticsearch Create func
	if err != nil { // catch error
        logger.Warnf("create req", err) // warn logging
		return
	}
}
```

`Infof` function is used to log informational application progress. Example:
```go
import (
	httpExample "github.com/forkyid/go-boilerplate/src/entity/v1/http/example"
	"github.com/forkyid/go-boilerplate/src/service/v1/example"
	"github.com/forkyid/go-utils/v1/logger"
	"github.com/gin-gonic/gin"
)

func Create(ctx *gin.Context) {
    req := httpExample.ConsumerCreateRequest{} // body request struct

    logger.Infof("publish to consumer") // info logging
    err = example.PublishToConsumer(req) // calling service example Elasticsearch Publish func
	if err != nil { // catch error
        logger.Warnf("publish to consumer", err) // warn logging
		return
	}
}
```

`Debugf` function is used to log informational events for troubleshooting. This will create the same error information like `Errorf` & `Fatalf`. Example:
```go
import (
	httpExample "github.com/forkyid/go-boilerplate/src/entity/v1/http/example"
	"github.com/forkyid/go-boilerplate/src/service/v1/example"
	"github.com/forkyid/go-utils/v1/logger"
    "github.com/forkyid/go-utils/v1/rest"
	"github.com/gin-gonic/gin"
)

func Create(ctx *gin.Context) {
    req := httpExample.CreateRequest{} // body request struct
    err := rest.BindJSON(ctx, &req) // bind json body request to struct request
	if err != nil { // catch error
		logger.Debugf(ctx, "bind json", err, req) // debug logging
		return
	}
}
```

### Ignore Body Struct Field
To ignore a credential struct field being logged, just like `password`. You can add a json struct tag `logignore:"true"`. Example:
```go
type CreateRequest struct {
	Username string `json:"username" example:"username" validate:"required"`
	Password string `json:"password" example:"password" validate:"required" logignore:"true"`
	Email    string `json:"email" example:"email@email.com" validate:"required,email"`
}
```