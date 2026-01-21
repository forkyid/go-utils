package logger

import (
	"bytes"
	"errors"
	"html/template"
	"net"
	"net/http"
	"os"
	"reflect"
	"runtime"
	"strings"

	"github.com/forkyid/go-utils/v1/uuid"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

var (
	logger *logrus.Logger
	cidrs  []*net.IPNet

	serverEnvironments = map[string]bool{
		"production":  true,
		"staging":     true,
		"development": true,
	}
)

const (
	tagJson      = "json"
	tagLogIgnore = "logignore"
)

func init() {
	if logger == nil {
		logger = logrus.New()
		env := os.Getenv("ENV")
		if serverEnvironments[env] {
			logger.SetLevel(logrus.ErrorLevel)
			logger.SetFormatter(&logrus.JSONFormatter{})
			logger.SetOutput(os.Stdout)
		} else {
			logger.SetLevel(logrus.DebugLevel)
			logger.SetFormatter(&logrus.TextFormatter{
				FullTimestamp: true,
				ForceColors:   true,
				DisableQuote:  true,
			})
		}
	}
	maxCidrBlocks := []string{
		"127.0.0.1/8",    // localhost
		"10.0.0.0/8",     // 24-bit block
		"172.16.0.0/12",  // 20-bit block
		"192.168.0.0/16", // 16-bit block
		"169.254.0.0/16", // link local address
		"::1/128",        // localhost IPv6
		"fc00::/7",       // unique local address IPv6
		"fe80::/10",      // link local address IPv6
	}
	cidrs = make([]*net.IPNet, len(maxCidrBlocks))
	for i, maxCidrBlock := range maxCidrBlocks {
		_, cidr, _ := net.ParseCIDR(maxCidrBlock)
		cidrs[i] = cidr
	}
}

// isPrivateAddress works by checking if the address is under private CIDR blocks.
// List of private CIDR blocks can be seen on:
//
// https://en.wikipedia.org/wiki/Private_network
//
// https://en.wikipedia.org/wiki/Link-local_address
func isPrivateAddress(address string) (isPrivate bool, err error) {
	ipAddress := net.ParseIP(address)
	if ipAddress == nil {
		isPrivate = false
		err = errors.New("address is not valid")
		return
	}

	for i := range cidrs {
		if cidrs[i].Contains(ipAddress) {
			isPrivate = true
			return
		}
	}

	isPrivate = false
	return
}

// realIP returns client's real public IP address from http request headers.
func realIP(req *http.Request) (ip string) {
	ip = req.Header.Get("X-Real-Ip") // Fetch header value
	xForwardedFor := req.Header.Get("X-Forwarded-For")
	if ip == "" && xForwardedFor == "" { // If both empty, return IP from remote address
		if strings.ContainsRune(req.RemoteAddr, ':') { // If there are colon in remote address, remove the port number
			ip, _, _ = net.SplitHostPort(req.RemoteAddr)
		} else { // otherwise, return remote address as is
			ip = req.RemoteAddr
		}
		return
	}

	for _, address := range strings.Split(xForwardedFor, ",") { // Check list of IP in X-Forwarded-For and return the first global address
		address = strings.TrimSpace(address)
		isPrivate, err := isPrivateAddress(address)
		if !isPrivate && err == nil {
			ip = address
			return
		}
	}
	return // If nothing succeed, return X-Real-Ip
}

// traceStack returns the last 6 stack error information about function invocations.
func traceStack() (stack string) {
	stack = ""
	ut, _ := template.New("stack").Parse("\n\t{{ .Name }} {{ .File }}:{{ .Line }}")
	for i := 1; i < 6; i++ {
		if pc, file, line, ok := runtime.Caller(i); ok {
			buf := new(bytes.Buffer)
			ut.Execute(buf, struct {
				Name string
				File string
				Line int
			}{
				Name: runtime.FuncForPC(pc).Name(),
				File: file,
				Line: line,
			})
			stack += buf.String()
		}
	}
	return
}

// parseBody parses the binded request struct from request body to map[string]string.
// Adding `logIgnore` will ignore the fields to be parsed.
func parseBody(v interface{}) (body map[string]string) {
	if v == nil || reflect.TypeOf(v).Kind() != reflect.Slice || reflect.ValueOf(v).Len() == 0 {
		return
	}

	val := reflect.ValueOf(v).Index(0)
	if val.Kind() == reflect.Interface && val.Elem().Kind() == reflect.Struct {
		val = val.Elem()
	} else if val.Kind() == reflect.Interface && val.Elem().Kind() == reflect.Slice {
		val = val.Elem().Index(0).Elem()
	} else {
		return
	}

	t := val.Type()
	body = map[string]string{}
	for i := 0; i < val.NumField(); i++ {
		field := t.Field(i)
		logIgnore := field.Tag.Get(tagLogIgnore)
		if logIgnore == "true" {
			continue
		}
		body[field.Tag.Get(tagJson)] = val.Field(i).String()
	}
	return
}

// defineFields returns logrus logging Fields defined from gin context and optional args.
// Those 10 fields are: Key, ServiceName, Params, StatusCode, Trace, Request URI, Method, IP, Remote Address, and Body (from optional args).
// Optional args is the binded request body struct.
// Only the first args interface will be parsed no matter how many args are passed.
func defineFields(ctx *gin.Context, args ...interface{}) (fields logrus.Fields) {
	fields = logrus.Fields{
		"ServiceName": os.Getenv("SERVICE_NAME"),
		"Trace":       traceStack(),
	}
	if len(args) > 0 {
		fields["Body"] = parseBody(args[0])
	}

	if ctx == nil {
		return
	}

	getRequestID, ok := ctx.Get("response_id")
	if !ok || getRequestID == "" {
		getRequestID = uuid.GetUUID()
	} else {
		getRequestID = getRequestID.(string)
	}
	fields["Key"] = getRequestID

	params := map[string]string{}
	for _, p := range ctx.Params {
		params[p.Key] = p.Value
	}
	fields["Params"] = params
	fields["StatusCode"] = ctx.Writer.Status()
	req := ctx.Request
	if req != nil {
		fields["Request"] = req.RequestURI
		fields["Method"] = req.Method
		fields["IP"] = realIP(req)
		fields["RemoteAddress"] = req.Header.Get("X-Request-Id")
	}
	return
}

// Fatalf is used to log very severe error events.
func Fatalf(ctx *gin.Context, errMsg string, err error, args ...interface{}) {
	logger.WithFields(defineFields(ctx, args)).Fatalf(errMsg+": %v", err)
}

// Errorf is used to log issues that preventing the application to properly functioning.
func Errorf(ctx *gin.Context, errMsg string, err error, args ...interface{}) {
	logger.WithFields(defineFields(ctx, args)).Errorf(errMsg+": %v", err)
}

// Warnf is used to log potentially harmful events.
func Warnf(errMsg string, err error) {
	logger.WithFields(logrus.Fields{"Trace": traceStack()}).Warnf(errMsg+": %v", err)
}

// Infof is used to log informational application progress.
func Infof(infoMsg string) {
	logger.WithFields(logrus.Fields{}).Info(infoMsg)
}

// Debugf is used to log informational events for troubleshooting.
func Debugf(ctx *gin.Context, errMsg string, err error, args ...interface{}) {
	logger.WithFields(defineFields(ctx, args)).Debugf(errMsg+": %v", err)
}
