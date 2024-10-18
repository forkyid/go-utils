package rest

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/forkyid/go-utils/v1/logger"
	publisher "github.com/forkyid/go-utils/v1/nsq/publisher/v1"
	"github.com/forkyid/go-utils/v1/pagination"
	uuid "github.com/forkyid/go-utils/v1/uuid"
	"github.com/gin-gonic/gin"
	"github.com/globalsign/mgo/bson"
	"github.com/go-playground/validator/v10"
)

// Response types
type Response struct {
	Result  interface{}       `json:"result,omitempty"`
	Error   string            `json:"error,omitempty"`
	Message string            `json:"message,omitempty"`
	Detail  map[string]string `json:"detail,omitempty"`
	Status  int               `json:"status,omitempty"`
}

// ResponsePaginationResult types
type ResponsePaginationResult struct {
	Data      interface{} `json:"data"`
	TotalData int         `json:"total_data"`
	Page      int         `json:"page"`
	TotalPage int         `json:"total_page"`
}

// ResponsePaginationParams types
type ResponsePaginationParams struct {
	Data       interface{}
	TotalData  int
	Pagination *pagination.Pagination
}

// ResponseResult types
type ResponseResult struct {
	Context *gin.Context
	UUID    string
}

// Log uses current response context to log
func (resp ResponseResult) Log(errMsg string, err error, args ...interface{}) {
	resp.Context.Set("response_id", resp.UUID)
	if args == nil || (len(args) > 0 && args[0] == nil) { // send nil interface if no value
		logger.Errorf(resp.Context, errMsg, err, nil)
		return
	}
	logger.Errorf(resp.Context, errMsg, err, args)
}

// ErrorDetails contains '|' separated details for each field
type ErrorDetails map[string]string

// Validator validator
var Validator = validator.New()

// Add adds details to key separated by '|'
func (details *ErrorDetails) Add(key, val string) {
	if (*details)[key] != "" {
		(*details)[key] += " | "
	}
	(*details)[key] += val
}

// ResponseData params
// @context: *gin.Context
// status: int
// msg: string
func ResponseData(context *gin.Context, status int, payload interface{}, msg ...string) ResponseResult {
	if len(msg) > 1 {
		log.Println("response cannot contain more than one message")
		log.Println("proceeding with first message only...")
	}
	if len(msg) == 0 {
		msg = []string{http.StatusText(status)}
	}

	response := Response{
		Result:  payload,
		Message: msg[0],
	}

	var copied gin.Context = *context
	PublishLog(&copied, status, payload, msg[0])
	context.JSON(status, response)
	return ResponseResult{context, uuid.GetUUID()}
}

// ResponsePagination params
// @context: *gin.Context
// @status: int
// @params: ResponsePaginationParams
// return ResponseResult
func ResponsePagination(context *gin.Context, status int, params ResponsePaginationParams) ResponseResult {
	msg := http.StatusText(status)

	if params.Pagination == nil {
		log.Println("proceeding with default pagination value")
		params.Pagination = &pagination.Pagination{}
		params.Pagination.Paginate()
	}

	if params.TotalData == 0 {
		log.Println("proceeding with 0 total_data...")
	}

	response := Response{
		Result: ResponsePaginationResult{
			Data:      params.Data,
			TotalData: params.TotalData,
			Page:      params.Pagination.Page,
			TotalPage: params.TotalData / params.Pagination.Limit,
		},
		Message: msg,
	}

	var copied gin.Context = *context
	PublishLog(&copied, status, params.Data, msg)
	context.JSON(status, response)
	return ResponseResult{context, uuid.GetUUID()}
}

// ResponseMessage params
// @context: *gin.Context
// status: int
// msg: string
func ResponseMessage(context *gin.Context, status int, msg ...string) ResponseResult {
	if len(msg) > 1 {
		log.Println("response cannot contain more than one message")
		log.Println("proceeding with first message only...")
	}
	if len(msg) == 0 {
		msg = []string{http.StatusText(status)}
	} else if status < 200 || status > 299 {
		log.Println("[GOUTILS-debug]", msg[0])
	}

	response := Response{
		Message: msg[0],
	}
	if status < 200 || status > 299 {
		response.Error = uuid.GetUUID()
	}

	var copied gin.Context = *context
	PublishLog(&copied, status, nil, msg[0])
	context.JSON(status, response)
	return ResponseResult{context, response.Error}
}

// ResponseError params
// @context: *gin.Context
// status: int
// msg: string
// detail: array
func ResponseError(context *gin.Context, status int, detail interface{}, msg ...string) ResponseResult {
	if len(msg) > 1 {
		log.Println("response cannot contain more than one message")
		log.Println("proceeding with first message only...")
	}
	if len(msg) == 0 {
		msg = []string{http.StatusText(status)}
	}

	response := Response{
		Error:   uuid.GetUUID(),
		Message: msg[0],
	}

	if det, ok := detail.(validator.ValidationErrors); ok {
		response.Detail = map[string]string{}
		for _, err := range det {
			response.Detail[strings.ToLower(err.Field())] = err.Tag()
		}
	} else if det, ok := detail.(map[string]string); ok {
		response.Detail = det
	} else if det, ok := detail.(*ErrorDetails); ok {
		response.Detail = *det
	} else if det, ok := detail.(string); ok {
		response.Detail = map[string]string{}
		response.Detail["error"] = det
	}

	log.Printf("[GOUTILS-debug] %+v\n", response)

	var copied gin.Context = *context
	PublishLog(&copied, status, response.Detail, msg[0])
	context.JSON(status, response)
	return ResponseResult{context, response.Error}
}

// MultipartForm creates multipart payload
func MultipartForm(fileKey string, files [][]byte, params map[string]string, multiParams map[string][]string) (io.Reader, string) {
	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	for _, j := range files {
		part, _ := writer.CreateFormFile(fileKey, bson.NewObjectId().Hex())
		part.Write(j)
	}
	for k, v := range multiParams {
		for _, j := range v {
			writer.WriteField(k, j)
		}
	}
	for k, v := range params {
		writer.WriteField(k, v)
	}
	err := writer.Close()
	if err != nil {
		return nil, ""
	}

	return body, writer.FormDataContentType()
}

// GetData unwraps "result" object
func GetData(jsonBody []byte) (json.RawMessage, error) {
	body := map[string]json.RawMessage{}
	err := json.Unmarshal(jsonBody, &body)
	if err != nil {
		return nil, err
	}
	data := body["result"]
	return data, err
}

// PublishLog params
//
//	@context: *gin.Context
//	@status: int
//	@payload: interface
//	@msg: []string
//	@return error
func PublishLog(context *gin.Context, status int, payload interface{}, msg ...string) error {
	requestBody, err := ioutil.ReadAll(context.Request.Body)
	if err != nil {
		log.Println("read body failed " + err.Error())
		return nil
	}

	contentType := context.GetHeader("Content-Type")
	var requestBodyInterface map[string]interface{}
	if contentType == "application/json" && len(requestBody) > 0 {
		err = json.Unmarshal(requestBody, &requestBodyInterface)
		if err != nil {
			log.Println("unmarshal data failed " + err.Error())
			return nil
		}
	}

	body := &LogData{
		Request: LogRequest{
			Method:          context.Request.Method,
			URL:             context.Request.URL,
			Header:          context.Request.Header,
			Body:            requestBodyInterface,
			Host:            context.Request.Host,
			Form:            context.Request.Form,
			PostForm:        context.Request.PostForm,
			MultipartForm:   context.Request.MultipartForm,
			RemoteAddr:      context.Request.RemoteAddr,
			PublicIPAddress: context.ClientIP(),
			RequestURI:      context.Request.RequestURI,
		},
		Response: Response{
			Result:  payload,
			Status:  status,
			Message: msg[0],
		},
	}

	location, err := time.LoadLocation(os.Getenv("SERVER_TIMEZONE"))
	if err != nil {
		log.Println("failed on get location: " + err.Error())
		return nil
	}

	timestamp := time.Now().In(location).Unix()
	data, err := json.Marshal(map[string]interface{}{
		"service_name": os.Getenv("SERVICE_NAME"),
		"payload":      body,
		"timestamp":    timestamp,
	})
	if err != nil {
		log.Println("failed on encoding json: " + err.Error())
		return nil
	}

	err = publisher.Publish(data)
	if err != nil {
		log.Println("publish data failed " + err.Error())
		return nil
	}

	return nil
}
