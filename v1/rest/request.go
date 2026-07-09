package rest

import (
	"context"
	"io"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

// Request type
type Request struct {
	URL     string
	Method  string
	Headers map[string]string
	Body    io.Reader
	Queries map[string]string
}

// ValidMethod params
// @method: string
// return bool
func ValidMethod(method string) bool {
	switch method {
	default:
		return false
	case
		http.MethodConnect,
		http.MethodDelete,
		http.MethodGet,
		http.MethodHead,
		http.MethodOptions,
		http.MethodPatch,
		http.MethodPost,
		http.MethodPut,
		http.MethodTrace:
		return true
	}
}

// Deprecated: use SendWithContext
func (request *Request) Send() ([]byte, int) {
	return request.SendWithContext(context.Background())
}

func (request *Request) SendWithContext(ctx context.Context) ([]byte, int) {
	if !ValidMethod(request.Method) {
		log.Println("[WARN] Unsupported method supplied, use one of constants provided by http package (e.g. http.MethodGet)")
		return nil, -1
	}

	req, _ := http.NewRequestWithContext(ctx, request.Method, request.URL, request.Body)

	for k, v := range request.Headers {
		req.Header.Set(k, v)
	}

	if request.Method == http.MethodGet {
		q := req.URL.Query()
		for k, v := range request.Queries {
			q.Add(k, v)
		}
		req.URL.RawQuery = q.Encode()
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Println("ERROR: ["+request.Method+"]", err.Error())
		return nil, -1
	}

	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)

	return body, resp.StatusCode
}

// WithContext params
// @ctx: *gin.Context
// return *Request
func (request *Request) WithContext(ctx *gin.Context) *Request {
	if request.Headers == nil {
		request.Headers = map[string]string{}
	}
	for k, v := range ctx.Request.Header {
		if len(v) > 0 {
			request.Headers[k] = v[0]
		}
	}
	return request
}
